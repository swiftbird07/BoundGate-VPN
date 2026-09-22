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
    private var callback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        node.service = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            worker.execute { down() }
            return START_NOT_STICKY
        }
        foreground()
        watchNetwork()
        worker.execute {
            try {
                // Connect and Always-on may both start the service: once is enough
                if (node.call("GET", "/v1/status").optString("state") != "down") return@execute
                node.call("POST", "/v1/up", JSONObject().put("profile", ""))
            } catch (e: Exception) {
                Log.w(Node.TAG, "up: ${e.message}")
                node.tunnelError = e.message
                stopTunnel()
            }
        }
        return START_STICKY
    }

    private fun down() {
        try {
            node.call("POST", "/v1/down")
        } catch (e: Exception) {
            Log.w(Node.TAG, "down: ${e.message}")
        }
        stopTunnel() // also when the overlay was not up and nothing is released
    }

    /** The user or another VPN app took the VPN away. */
    override fun onRevoke() {
        worker.execute { down() }
    }

    override fun onDestroy() {
        callback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        callback = null
        if (node.service === this) node.service = null
        worker.shutdown()
        super.onDestroy()
    }

    /** Builds the interface for the core's settings and hands its descriptor over (the core owns it). */
    fun establish(s: JSONObject): Int {
        val b = Builder().setSession("BoundGate").setMtu(s.getInt("mtu"))
        prefix(s.getString("address")).let { (a, bits) -> b.addAddress(a, bits) }
        s.optJSONArray("routes")?.let { r ->
            for (i in 0 until r.length()) prefix(r.getString(i)).let { (a, bits) -> b.addRoute(a, bits) }
        }
        val outside = mutableSetOf<InetAddress>()
        s.optJSONArray("excluded")?.let { e -> for (i in 0 until e.length()) outside += InetAddress.getByName(e.getString(i)) }
        val offered = s.optJSONArray("dns")?.let { d -> (0 until d.length()).map { InetAddress.getByName(d.getString(it)) } }.orEmpty()
        if (offered.isNotEmpty()) {
            // the hub's resolvers, and only those: the core routes them
            // through the tunnel and the hub lets DNS to them through
            offered.forEach { b.addDnsServer(it) }
        } else {
            below?.dnsServers?.forEach {
                b.addDnsServer(it)
                outside += it
            }
            below?.domains?.split(' ')?.filter { it.isNotBlank() }?.forEach { b.addSearchDomain(it) }
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
        return pfd.detachFd()
    }

    /** The core took the overlay down and closed the interface. */
    fun released() {
        stopTunnel()
    }

    private fun stopTunnel() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun prefix(p: String): Pair<String, Int> {
        val i = p.lastIndexOf('/')
        return p.substring(0, i) to p.substring(i + 1).toInt()
    }

    /**
     * Wi-Fi <-> cellular: the core reconnects the control channel and the hub
     * links at once and hands the settings over again, so the VPN gets the
     * new network's DNS servers.
     */
    private fun watchNetwork() {
        if (callback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                if (network == n) return
                val changed = network != null
                network = n
                below = cm.getLinkProperties(n)
                setUnderlyingNetworks(arrayOf(n))
                if (changed) node.networkChanged()
            }

            override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
                if (n != network) return
                val dnsChanged = below?.dnsServers != lp.dnsServers
                below = lp
                if (dnsChanged) node.networkChanged()
            }

            override fun onLost(n: Network) {
                if (network == n) {
                    network = null
                    below = null
                }
            }
        }
        // now, before the first establish; the callback may come later
        cm.activeNetwork?.let { n ->
            if (cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false) {
                network = n
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
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.net407.boundgate.CONNECT"
        const val ACTION_DISCONNECT = "com.net407.boundgate.DISCONNECT"
        private const val CHANNEL = "tunnel"
    }
}
