package com.net407.boundgate

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * The tunnel as Android sees it. The core runs in the app's process (Node);
 * this service brings the overlay up, builds the interface when the core
 * asks for one (every change of routes is a new interface: establish()), and
 * stops when the core releases it. The app's own sockets stay outside the
 * tunnel (addDisallowedApplication), so the control channel and the hub
 * links never go through themselves.
 *
 * DNS: apps inside a VPN without DNS servers resolve nothing. When the
 * primary hub offers resolvers (hub option `dns`), the VPN uses those only,
 * through the tunnel. Otherwise it carries the DNS servers of the network
 * below, and their addresses stay outside the tunnel, as on the other
 * platforms where the system resolver is used as it is. The
 * same goes for the `excluded` hosts (control plane, hubs, IdP): the browser
 * must reach the IdP to sign in before the hub lets anything through.
 * In lockdown nothing but the tunnel is open to other apps; there the hub's
 * login_passthrough carries the way to the sign-in instead.
 *
 * Started by the app's Connect, by Always-on VPN (action
 * android.net.VpnService), or again by the system after the process died
 * (START_STICKY, null intent): all of them mean "connect".
 */
class TunnelService : VpnService() {

    private val node get() = (application as App).node
    private val worker = Executors.newSingleThreadExecutor()
    // the network below the VPN and its properties (never the VPN itself)
    @Volatile private var network: Network? = null
    @Volatile private var below: LinkProperties? = null
    // whether Android has confirmed that network reaches the internet
    @Volatile private var validated = false
    // whether any network below was seen since the service started: the
    // first one is where the core starts, not a change
    @Volatile private var seen = false
    // the VPN carries the resolvers of the network below (no hub resolvers):
    // then a change of those is a change of the interface
    @Volatile private var usesBelowDNS = false
    private var callback: ConnectivityManager.NetworkCallback? = null
    // what the interface the core holds was built from, and its descriptor
    @Volatile private var applied: Pair<String, Int>? = null

    override fun onCreate() {
        super.onCreate()
        DebugLog.log("svc", "created always_on=$isAlwaysOn lockdown=$isLockdownEnabled")
        node.service = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        DebugLog.log("svc", "start action=${intent?.action} flags=$flags id=$startId")
        if (intent?.action == ACTION_DISCONNECT) {
            worker.execute { down() }
            return START_NOT_STICKY
        }
        foreground()
        watchNetwork()
        worker.execute {
            try {
                // Connect and Always-on may both start the service: once is enough
                val state = node.call("GET", "/v1/status").optString("state")
                DebugLog.log("svc", "node state before up: $state")
                if (state != "down") return@execute
                node.call("POST", "/v1/up", JSONObject().put("profile", node.profile))
                DebugLog.log("svc", "up accepted profile=${node.profile}")
            } catch (e: Exception) {
                Log.w(Node.TAG, "up: ${e.message}")
                DebugLog.log("svc", "up failed: ${e.message}")
                node.tunnelError = e.message
                stopTunnel()
            }
        }
        return START_STICKY
    }

    private fun down() {
        DebugLog.log("svc", "down")
        try {
            node.call("POST", "/v1/down")
        } catch (e: Exception) {
            Log.w(Node.TAG, "down: ${e.message}")
            DebugLog.log("svc", "down failed: ${e.message}")
        }
        stopTunnel() // also when the overlay was not up and nothing is released
    }

    /** The user or another VPN app took the VPN away. */
    override fun onRevoke() {
        DebugLog.log("svc", "revoked by the system")
        worker.execute { down() }
    }

    override fun onDestroy() {
        DebugLog.log("svc", "destroyed")
        callback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        callback = null
        if (node.service === this) node.service = null
        worker.shutdown()
        super.onDestroy()
    }

    /**
     * Builds the interface for the core's settings and hands its descriptor
     * over (the core owns it). The core hands the settings over again after
     * every change of network (for the resolvers of the network below). The
     * same interface again, in the middle of the phone joining a Wi-Fi, left
     * it without internet until the VPN was switched off and on (reported
     * 2026-10-26; iOS had the same, 2026-09-22): when nothing that goes into
     * the interface changed, the one the core holds is kept, and only the
     * network underneath is told to it (setUnderlyingNetworks, watchNetwork).
     */
    fun establish(s: JSONObject): Int {
        val lp = below
        val offered = s.optJSONArray("dns")?.let { d -> (0 until d.length()).map { InetAddress.getByName(d.getString(it)) } }.orEmpty()
        usesBelowDNS = offered.isEmpty()
        val fromBelow = if (offered.isEmpty()) "${lp?.dnsServers} ${lp?.domains}" else ""
        val key = "$s lockdown=$isLockdownEnabled below=$fromBelow"
        applied?.let { (k, fd) ->
            if (k == key) {
                Log.i(Node.TAG, "establish: unchanged, interface $fd kept")
                DebugLog.log("tun", "settings unchanged, interface fd=$fd kept (network=$network)")
                return fd
            }
        }
        DebugLog.log("tun", "new interface: $key network=$network below_iface=${lp?.interfaceName} below_dns=${lp?.dnsServers} previous=${applied?.second}")
        val b = Builder().setSession("BoundGate").setMtu(s.getInt("mtu"))
        prefix(s.getString("address")).let { (a, bits) -> b.addAddress(a, bits) }
        s.optJSONArray("routes")?.let { r ->
            for (i in 0 until r.length()) prefix(r.getString(i)).let { (a, bits) -> b.addRoute(a, bits) }
        }
        val outside = mutableSetOf<InetAddress>()
        s.optJSONArray("excluded")?.let { e -> for (i in 0 until e.length()) outside += InetAddress.getByName(e.getString(i)) }
        if (offered.isNotEmpty()) {
            // the hub's resolvers, and only those: the core routes them
            // through the tunnel and the hub lets DNS to them through
            offered.forEach { b.addDnsServer(it) }
        } else {
            lp?.dnsServers?.forEach {
                b.addDnsServer(it)
                outside += it
            }
            lp?.domains?.split(' ')?.filter { it.isNotBlank() }?.forEach { b.addSearchDomain(it) }
        }
        // Always-on with "Block connections without VPN" blocks every other
        // app's traffic outside the tunnel, excluded or not: then the IdP and
        // DNS go through it, to a hub with login_passthrough (docs/ANDROID.md)
        if (!isLockdownEnabled) {
            for (a in outside) b.excludeRoute(IpPrefix(a, if (a.address.size == 4) 32 else 128))
        }
        b.addDisallowedApplication(packageName)
        b.setConfigureIntent(openApp())
        network?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        val pfd = b.establish() ?: throw IllegalStateException("Android does not let BoundGate set up the VPN (was the permission revoked?)")
        val fd = pfd.detachFd()
        applied = key to fd
        DebugLog.log("tun", "interface established fd=$fd")
        return fd
    }

    /** The core took the overlay down and closed the interface. */
    fun released() {
        DebugLog.log("tun", "released by the core (fd=${applied?.second})")
        applied = null
        stopTunnel()
    }

    private fun stopTunnel() {
        applied = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun prefix(p: String): Pair<String, Int> {
        val i = p.lastIndexOf('/')
        return p.substring(0, i) to p.substring(i + 1).toInt()
    }

    /** Tells the core; every call is in the debug log with its reason. */
    private fun changed(why: String) {
        DebugLog.log("net", "-> core: network changed ($why)")
        node.networkChanged()
    }

    /**
     * Wi-Fi <-> cellular: the core reconnects the control channel and the hub
     * links at once (new sockets; QUIC connection migration) and hands the
     * settings over again, so the VPN gets the new network's DNS servers.
     *
     * The default network callback of this app (which the VPN leaves out)
     * reports the network underneath. Any network other than the one the
     * core is on is a change -- also the first one after a gap with none,
     * which is how walking out of a Wi-Fi, a switch from one Wi-Fi to
     * another and airplane mode present themselves: onLost, then a new
     * network. Until 2026-10-28 that counted as "the first network", the
     * core was not told, and its tunnels sat on sockets of a network that
     * was gone. Only the network the service starts on is no change. The
     * same network becoming validated (Android confirmed it reaches the
     * internet) is passed on too: a dial that failed while it was coming up
     * gets its retry at once.
     */
    private fun watchNetwork() {
        if (callback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) {
                DebugLog.log("net", "available $n")
            }

            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
                DebugLog.log("net", "capabilities $n: $caps")
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                val ok = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                if (network == n) {
                    val was = validated
                    validated = ok
                    if (ok && !was) changed("network $n validated")
                    return
                }
                val first = !seen
                seen = true
                network = n
                validated = ok
                below = cm.getLinkProperties(n)
                setUnderlyingNetworks(arrayOf(n))
                if (!first) changed("network $n (validated=$ok)")
            }

            override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
                DebugLog.log("net", "link $n: $lp")
                if (n != network) return
                val dnsChanged = below?.dnsServers != lp.dnsServers
                below = lp
                // with the hub's resolvers in the VPN, those of the network
                // below are nothing the interface carries
                if (dnsChanged && usesBelowDNS) changed("resolvers of the network below")
            }

            override fun onLost(n: Network) {
                DebugLog.log("net", "lost $n (current=$network)")
                if (network == n) {
                    network = null
                    below = null
                    validated = false
                }
            }

            override fun onBlockedStatusChanged(n: Network, blocked: Boolean) {
                DebugLog.log("net", "blocked $n: $blocked")
            }

            override fun onUnavailable() {
                DebugLog.log("net", "unavailable")
            }
        }
        // now, before the first establish; the callback may come later
        cm.activeNetwork?.let { n ->
            val caps = cm.getNetworkCapabilities(n)
            DebugLog.log("net", "active at start: $n $caps")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false) {
                network = n
                seen = true
                validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                below = cm.getLinkProperties(n)
            }
        }
        // the default network of this app, which the VPN leaves out: the one
        // underneath (the VPN itself shows up here too while it starts)
        cm.registerDefaultNetworkCallback(cb)
        callback = cb
    }

    private fun openApp(): PendingIntent =
        PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)

    private fun foreground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Connection", NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("BoundGate")
            .setContentText("Connected to your network")
            .setContentIntent(openApp())
            .setOngoing(true)
            .build()
        try {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } catch (e: Exception) {
            // the bound VpnService keeps running without it
            Log.w(Node.TAG, "no foreground notification: ${e.message}")
            DebugLog.log("svc", "no foreground notification: ${e.message}")
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.net407.boundgate.CONNECT"
        const val ACTION_DISCONNECT = "com.net407.boundgate.DISCONNECT"
        private const val CHANNEL = "tunnel"
    }
}
