package com.net407.boundgate

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The Quick Settings tile: one tap connects or disconnects, like the app's
 * own button. It acts only where the app would act without asking anything:
 * a device that is not approved yet, a VPN permission Android has not given
 * (the first connect, or another VPN app holds it) and a start Android
 * refuses from the background all open the app instead, which then
 * continues with the same step (MainActivity.ACTION_CONNECT).
 *
 * The tile follows the tunnel: Node.statusChanged asks the system to
 * listen again whenever what the tile shows changes.
 */
class VpnTileService : TileService() {

    private val node get() = (application as App).node
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var shown = TileState.SETUP

    override fun onStartListening() {
        super.onStartListening()
        worker.execute {
            val s = TileState.of(try { node.call("GET", "/v1/status") } catch (e: Exception) { null })
            // the tile belongs to the main thread's callbacks
            android.os.Handler(mainLooper).post { show(s) }
        }
    }

    override fun onClick() {
        super.onClick()
        when (shown) {
            TileState.SETUP -> openApp(null)
            TileState.CONNECTING, TileState.CONNECTED, TileState.SIGN_IN -> {
                try {
                    startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_DISCONNECT))
                } catch (e: IllegalStateException) {
                    // the service is gone and may not be started from here:
                    // nothing holds the interface, the core only has to stop
                    worker.execute { try { node.call("POST", "/v1/down") } catch (e: Exception) { Log.w(Node.TAG, "tile: ${e.message}") } }
                }
                show(TileState.OFF)
            }
            TileState.OFF -> {
                if (VpnService.prepare(this) != null) {
                    // Android asks once per app (and again after another VPN
                    // app took over): that dialog needs an activity
                    openApp(MainActivity.ACTION_CONNECT)
                    return
                }
                try {
                    startForegroundService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_CONNECT))
                    show(TileState.CONNECTING)
                } catch (e: IllegalStateException) {
                    // ForegroundServiceStartNotAllowedException: the system
                    // did not count the tap as the user's; the app may start it
                    Log.w(Node.TAG, "tile: ${e.message}")
                    openApp(MainActivity.ACTION_CONNECT)
                }
            }
        }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun show(s: TileState) {
        val tile = qsTile ?: return
        shown = s
        tile.state = if (s.active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.subtitle = s.label
        tile.contentDescription = "BoundGate: ${s.label}"
        tile.updateTile()
    }

    private fun openApp(action: String?) {
        val intent = LaunchToken.stamp(this, Intent(this, MainActivity::class.java).setAction(action))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val go = {
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 1, intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            } else {
                @Suppress("DEPRECATION", "StartActivityAndCollapseDeprecated")
                startActivityAndCollapse(intent)
            }
        }
        if (isLocked) unlockAndRun { go() } else go()
    }

    /** What the tile shows; the same reading of the status as the app's phase. */
    enum class TileState(val label: String, val active: Boolean) {
        SETUP("Open the app", false),
        OFF("Off", false),
        CONNECTING("Connecting", true),
        SIGN_IN("Sign-in needed", true),
        CONNECTED("Connected", true);

        companion object {
            fun of(s: JSONObject?): TileState {
                if (s == null || s.optString("state") == "unconfigured" || s.optString("enrollment") != "approved") return SETUP
                if (s.optString("state") == "down") return OFF
                val hubs = s.optJSONArray("hubs")
                for (i in 0 until (hubs?.length() ?: 0)) if (hubs!!.getJSONObject(i).optString("state") == "connected") return CONNECTED
                return if (s.optBoolean("login_required")) SIGN_IN else CONNECTING
            }
        }
    }

    companion object {
        /** The tile shows the status the system last let it read: ask for a new reading. */
        fun refresh(context: Context) {
            try {
                requestListeningState(context, ComponentName(context, VpnTileService::class.java))
            } catch (e: Exception) {
                Log.w(Node.TAG, "tile: ${e.message}")
            }
        }
    }
}
