package com.net407.boundgate

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.PopupMenu
import android.widget.ScrollView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.time.OffsetDateTime
import java.util.concurrent.Executors

/**
 * The app's one screen, like the iOS app's (MobileView): a header with the
 * state, then one card for the step the device is at: set up, request
 * access, wait for approval, connect, sign in, connected.
 */
class MainActivity : Activity() {

    private enum class Phase { NO_ENGINE, UNCONFIGURED, NEEDS_ENROLL, PENDING, REVOKED, READY, CONNECTING, LOGIN_REQUIRED, CONNECTED }

    private val node get() = (application as App).node
    private val main = Handler(Looper.getMainLooper())
    private val pool = Executors.newCachedThreadPool()
    private lateinit var ui: Ui
    private lateinit var content: LinearLayout

    private var status: JSONObject? = null
    private var busy: String? = null
    private var actionError: String? = null
    private var pinToConfirm: String? = null
    private var loginInProgress = false
    private var connecting = false // between Connect and the service's first answer
    private var shown = "" // what the screen shows; it is rebuilt only when this changes

    // the setup card's fields, kept across rebuilds
    private var controlInput = ""
    private var nameInput = ""

    private val poll = object : Runnable {
        override fun run() {
            refresh()
            main.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ui = Ui(this, Theme.of(this))
        window.decorView.setBackgroundColor(ui.t.bg)
        content = ui.column(14).apply { setPadding(ui.dp(16), ui.dp(12), ui.dp(16), ui.dp(24)) }
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(content, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))
        }
        // edge to edge (Android 15+): keep clear of the bars and the keyboard
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val i = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime() or WindowInsets.Type.displayCutout())
            v.setPadding(i.left, i.top, i.right, i.bottom)
            insets
        }
        setContentView(scroll)
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
        render()
    }

    override fun onResume() {
        super.onResume()
        main.post(poll)
    }

    override fun onPause() {
        main.removeCallbacks(poll)
        super.onPause()
    }

    // MARK: state

    private val phase: Phase
        get() {
            val s = status ?: return Phase.NO_ENGINE
            if (s.optString("state") == "unconfigured") return Phase.UNCONFIGURED
            when (s.optString("enrollment")) {
                "approved" -> {}
                "pending", "confirmed" -> return Phase.PENDING
                "revoked" -> return Phase.REVOKED
                else -> return Phase.NEEDS_ENROLL
            }
            if (s.optString("state") == "down") return if (connecting) Phase.CONNECTING else Phase.READY
            if (hubs(s).any { it.optString("state") == "connected" }) return Phase.CONNECTED
            if (s.optBoolean("login_required")) return Phase.LOGIN_REQUIRED
            return Phase.CONNECTING
        }

    private fun hubs(s: JSONObject): List<JSONObject> = list(s.optJSONArray("hubs")).map { it as JSONObject }

    private fun list(a: JSONArray?): List<Any> = if (a == null) emptyList() else (0 until a.length()).map { a.get(it) }

    private fun strings(s: JSONObject, key: String) = list(s.optJSONArray(key)).map { it.toString() }

    private fun refresh() {
        pool.execute {
            val (code, json) = node.request("GET", "/v1/status")
            main.post {
                status = if (code == 200) json else null
                node.tunnelError?.let {
                    node.tunnelError = null
                    actionError = "The tunnel stopped: $it"
                    connecting = false
                }
                // the node is past "down": it says for itself how far it is
                if (connecting && status?.optString("state") != "down") connecting = false
                render()
            }
        }
    }

    private fun run(label: String, work: () -> Unit) {
        if (busy != null) return
        busy = label
        actionError = null
        render()
        pool.execute {
            val err = try {
                work()
                null
            } catch (e: Node.Refused) {
                if (e.controlPin != null) {
                    main.post { pinToConfirm = e.controlPin }
                    null
                } else {
                    e.message
                }
            } catch (e: Exception) {
                e.message ?: e.toString()
            }
            main.post {
                busy = null
                if (err != null) actionError = err
                refresh()
            }
        }
    }

    // MARK: actions

    private fun configure() {
        val control = controlInput.trim()
        val name = nameInput.trim()
        run("Saving") {
            val body = JSONObject().put("control_addr", control)
            if (name.isNotEmpty()) body.put("name", name)
            node.call("POST", "/v1/configure", body)
        }
    }

    private fun enroll(acceptPin: String?) {
        pinToConfirm = null
        run("Requesting access") {
            node.call("POST", "/v1/enroll", JSONObject().apply { if (acceptPin != null) put("accept_pin", acceptPin) })
        }
    }

    private fun connect() {
        actionError = null
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, VPN_CONSENT)
        } else {
            startTunnel()
        }
    }

    @Deprecated("the platform's own API; the app has no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_CONSENT) return
        if (resultCode == RESULT_OK) startTunnel() else actionError = "BoundGate needs your permission to set up the VPN."
        render()
    }

    private fun startTunnel() {
        connecting = true
        startForegroundService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_CONNECT))
        render()
    }

    private fun disconnect() {
        connecting = false
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_DISCONNECT))
        main.postDelayed({ refresh() }, 300)
    }

    private fun signIn() {
        if (busy != null) return
        busy = "Signing in"
        actionError = null
        render()
        pool.execute {
            try {
                val start = node.call("POST", "/v1/login")
                val url = Uri.parse(start.optString("url"))
                if (url.scheme != "https" && url.scheme != "http") throw IllegalStateException("The control plane sent no usable sign-in address.")
                main.post {
                    busy = null
                    loginInProgress = true
                    render()
                    startActivity(Intent(Intent.ACTION_VIEW, url))
                }
                // up to ~5 minutes, 25 s per long poll
                var result: JSONObject? = null
                for (i in 0 until 12) {
                    result = node.call("GET", "/v1/login/${start.optString("flow_id")}?wait=25s")
                    if (result.optString("status") != "pending") break
                }
                val failed = when (result?.optString("status")) {
                    "done" -> null
                    "failed" -> result.optString("error").ifEmpty { "The sign-in failed." }
                    else -> "The sign-in took too long."
                }
                main.post {
                    loginInProgress = false
                    if (failed != null) actionError = failed
                    refresh()
                }
            } catch (e: Exception) {
                main.post {
                    busy = null
                    loginInProgress = false
                    actionError = e.message
                    refresh()
                }
            }
        }
    }

    private fun menu(anchor: View) {
        val s = status ?: return
        val m = PopupMenu(this, anchor)
        if (s.optString("fingerprint").isNotEmpty()) m.menu.add(0, 1, 0, "Copy device fingerprint")
        if (s.optJSONObject("user") != null) m.menu.add(0, 2, 0, "Sign out")
        if (s.optString("state") != "unconfigured") m.menu.add(0, 3, 0, "Forget this control plane")
        m.menu.add(0, 4, 0, "Version ${s.optString("version")}").isEnabled = false
        m.setOnMenuItemClickListener {
            when (it.itemId) {
                1 -> {
                    getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("fingerprint", s.optString("fingerprint")))
                    Toast.makeText(this, "Fingerprint copied", Toast.LENGTH_SHORT).show()
                }
                2 -> run("Signing out") { node.call("POST", "/v1/logout") }
                3 -> {
                    disconnect()
                    run("Forgetting") { node.call("POST", "/v1/reset") }
                }
            }
            true
        }
        m.show()
    }

    // MARK: screen

    private fun render() {
        val s = status
        val p = phase
        // rebuild only when what is shown changes: a rebuild would take the focus out of a text field
        val key = listOf(p, busy, actionError, pinToConfirm, loginInProgress, s?.let { sig(it, p) }).toString()
        if (key == shown) return
        shown = key
        content.removeAllViews()
        content.addView(header(p), ui.fill())
        for (v in cards(p, s)) content.addView(v, ui.fill())
        actionError?.let { content.addView(ui.notice(Tone.BAD, it), ui.fill()) }
        if (s != null && s.optString("node_name").isNotEmpty()) {
            val kind = when (s.optString("key_kind")) {
                "android-strongbox" -> "key in StrongBox"
                "android-keystore" -> "key in the secure hardware"
                else -> "key in software"
            }
            content.addView(ui.text("${s.optString("node_name")} · $kind", 12.5f, ui.t.text3).apply { setPadding(ui.dp(4), 0, 0, 0) }, ui.fill())
        }
    }

    /** The fields of the status the current phase shows. */
    private fun sig(s: JSONObject, p: Phase): String = when (p) {
        Phase.CONNECTED, Phase.CONNECTING, Phase.LOGIN_REQUIRED, Phase.READY -> listOf(
            s.optString("overlay_ip"), s.optJSONArray("hubs")?.toString(), s.optJSONObject("user")?.optString("username"),
            s.optJSONArray("routes")?.toString(), s.optJSONArray("skipped_routes")?.toString(), s.optString("last_error"),
            s.optString("binding_error"), s.optString("control_error"),
        ).toString()
        else -> listOf(s.optString("enrollment"), s.optString("fingerprint"), s.optString("control"), s.optString("control_error"), s.optString("enrollment_error"), s.optString("node_name")).toString()
    }

    private fun header(p: Phase) = ui.row().apply {
        addView(LogoTile(context, ui.t), LinearLayout.LayoutParams(ui.dp(36), ui.dp(36)))
        addView(
            ui.text("BoundGate", 21f, ui.t.text, ui.display).apply { setPadding(ui.dp(10), 0, 0, 0) },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        val (label, tone) = busy?.let { it to Tone.ACCENT } ?: when (p) {
            Phase.CONNECTED -> "Connected" to Tone.OK
            Phase.CONNECTING -> "Connecting" to Tone.ACCENT
            Phase.LOGIN_REQUIRED -> "Sign-in needed" to Tone.ACCENT
            Phase.READY -> "Disconnected" to Tone.IDLE
            Phase.PENDING -> "Awaiting approval" to Tone.ACCENT
            Phase.REVOKED -> "Revoked" to Tone.BAD
            Phase.NEEDS_ENROLL, Phase.UNCONFIGURED -> "Setup" to Tone.ACCENT
            Phase.NO_ENGINE -> "Not running" to Tone.IDLE
        }
        addView(ui.pill(label, tone))
        val more = ui.text("⋯", 22f, ui.t.text2, ui.display).apply {
            setPadding(ui.dp(14), ui.dp(2), ui.dp(4), ui.dp(2))
            gravity = Gravity.CENTER
            contentDescription = "More"
        }
        more.setOnClickListener { menu(it) }
        addView(more)
    }

    private fun cards(p: Phase, s: JSONObject?): List<View> = when (p) {
        Phase.NO_ENGINE -> listOf(ui.card(ui.title("BoundGate is not running"), ui.para(node.startError ?: "Starting…")))
        Phase.UNCONFIGURED -> listOf(setupCard(s))
        Phase.NEEDS_ENROLL -> listOf(enrollCard(s!!))
        Phase.PENDING -> listOf(
            ui.card(
                ui.title("Waiting for your administrator"),
                ui.para(
                    if (s!!.optString("enrollment") == "confirmed") {
                        "Confirmed. The last step is the administrator's signature; this screen updates by itself."
                    } else {
                        "Give this fingerprint to your administrator over a channel you trust. They compare all of it before they approve this device."
                    },
                ),
                ui.fingerprint("Fingerprint of this device", s.optString("fingerprint")),
            ),
        )
        Phase.REVOKED -> listOf(
            ui.card(
                ui.title("This device was revoked"),
                ui.para("An administrator revoked this device's key. A revoked key never comes back; ask your administrator how to proceed."),
            ),
        )
        else -> connectionCards(p, s!!)
    }

    private fun setupCard(s: JSONObject?): View {
        if (nameInput.isEmpty()) nameInput = s?.optString("node_name") ?: ""
        return ui.card(
            ui.title("Which network is this device joining?"),
            ui.para("Enter the address of your BoundGate control plane. Your administrator has it."),
            ui.field("vpn.example.com", controlInput, monoText = true, lowercase = true) { controlInput = it; renderSetupButton() },
            ui.field("Device name", nameInput, monoText = false, lowercase = false) { nameInput = it },
            setupButton(),
        )
    }

    private var setupButtonView: View? = null

    private fun setupButton() = ui.button("Continue", "primary", enabled = controlInput.isNotBlank() && busy == null) { configure() }
        .also { setupButtonView = it }

    private fun renderSetupButton() {
        val old = setupButtonView ?: return
        val parent = old.parent as? LinearLayout ?: return
        val i = parent.indexOfChild(old)
        parent.removeViewAt(i)
        parent.addView(setupButton(), i, ui.fill())
    }

    private fun enrollCard(s: JSONObject): View {
        val views = mutableListOf<View>(ui.title("Request access"), ui.info("Control plane", s.optString("control").ifEmpty { "–" }, monoValue = true))
        val err = listOf(s.optString("control_error"), s.optString("enrollment_error")).firstOrNull { it.isNotEmpty() }
        if (err != null && pinToConfirm == null && !err.contains("has not been accepted yet")) views += ui.notice(Tone.WARN, err)
        val pin = pinToConfirm
        if (pin != null) {
            views += ui.fingerprint("Control plane key", pin)
            views += ui.text(
                "This device has not talked to this control plane before and will trust this key from now on. Compare it with the fingerprint your administrator gave you. If it differs, somebody else is answering at that address: do not continue.",
                13f, ui.t.text2,
            )
            views += ui.button("It matches: request access", "primary", busy == null) { enroll(pin) }
            views += ui.button("Cancel") { pinToConfirm = null; render() }
        } else {
            views += ui.button("Request access", "primary", busy == null) { enroll(null) }
        }
        return ui.card(*views.toTypedArray())
    }

    private fun connectionCards(p: Phase, s: JSONObject): List<View> {
        val views = mutableListOf<View>()
        val hubs = hubs(s)
        when (p) {
            Phase.CONNECTED -> {
                val hub = hubs.firstOrNull { it.optBoolean("primary") && it.optString("state") == "connected" }
                    ?: hubs.first { it.optString("state") == "connected" }
                views += ui.row().apply {
                    addView(ui.text(s.optString("overlay_ip"), 28f, ui.t.text, ui.display).apply { setTextIsSelectable(true) }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                    since(s)?.let { addView(ui.text(it, 12.5f, ui.t.text3)) }
                }
                views += ui.info("Through", hub.optString("name") + if (hub.optString("transport") == "tcp") " · over TCP" else "")
                s.optJSONObject("user")?.let { u ->
                    views += ui.info("Signed in as", u.optString("username").ifEmpty { u.optString("email").ifEmpty { u.optString("subject") } })
                }
                val routes = strings(s, "routes")
                views += ui.info("Networks", if (routes.isEmpty()) "none" else routes.joinToString(", "))
                views += ui.info("Traffic", "↓ ${bytes(hub.optLong("bytes_in"))}  ↑ ${bytes(hub.optLong("bytes_out"))}")
            }
            Phase.LOGIN_REQUIRED -> {
                views += ui.title("Sign in to finish connecting")
                views += ui.para(if (loginInProgress) "Continue in the browser, then come back here." else "The network wants to know who is using this device.")
            }
            Phase.CONNECTING -> {
                views += ui.title("Connecting…")
                for (h in hubs) views += ui.info(h.optString("name"), h.optString("error").ifEmpty { h.optString("state") })
            }
            else -> views += ui.title("Not connected")
        }
        for (r in strings(s, "skipped_routes")) views += ui.notice(Tone.WARN, "Not routed: $r")
        if (p != Phase.CONNECTED) s.optString("last_error").takeIf { it.isNotEmpty() }?.let { views += ui.notice(Tone.BAD, it) }
        s.optString("binding_error").takeIf { it.isNotEmpty() }?.let { views += ui.notice(Tone.BAD, "This device's approval does not verify: $it") }
        s.optString("control_error").takeIf { it.isNotEmpty() }?.let { views += ui.notice(Tone.WARN, "Control plane: $it") }

        val out = mutableListOf<View>(ui.card(*views.toTypedArray()))
        when (p) {
            Phase.READY -> out += ui.button("Connect", "primary", busy == null) { connect() }
            Phase.LOGIN_REQUIRED -> {
                out += ui.button(if (loginInProgress) "Waiting for the browser…" else "Sign in", "primary", !loginInProgress && busy == null) { signIn() }
                out += ui.button("Disconnect") { disconnect() }
            }
            else -> out += ui.button("Disconnect") { disconnect() }
        }
        return out
    }

    private fun since(s: JSONObject): String? {
        val t = s.optString("since").takeIf { it.isNotEmpty() && !it.startsWith("0001") } ?: return null
        return try {
            DateUtils.getRelativeTimeSpanString(OffsetDateTime.parse(t).toInstant().toEpochMilli()).toString()
        } catch (_: Exception) {
            null
        }
    }

    private fun bytes(n: Long): String = when {
        n >= 1L shl 30 -> String.format("%.1f GB", n / 1e9)
        n >= 1L shl 20 -> String.format("%.1f MB", n / 1e6)
        n >= 1L shl 10 -> String.format("%.0f kB", n / 1e3)
        else -> "$n B"
    }

    companion object {
        private const val VPN_CONSENT = 1
    }
}
