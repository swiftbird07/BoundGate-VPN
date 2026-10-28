package com.net407.boundgate

import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.Future

/**
 * The debug log: what the app and the core do around the tunnel, for a
 * problem that only shows on a phone that is somewhere else (no internet
 * after a change of network, 2026-10-28). Off by default; the menu switches
 * it on, which also sets the core to debug (Core.setLogLevel), and "Share
 * debug log" hands the file to any app (LogProvider).
 *
 * Written under the app's files (debug/boundgate-debug.log), 4 MB, one
 * older file kept. Each line carries the wall-clock time, the uptime (which
 * stops while the phone sleeps) and the elapsed real time (which does not):
 * a gap between the two is the phone asleep, which no timer of the core
 * runs through either.
 */
object DebugLog {
    private const val MAX = 4L shl 20
    private const val NAME = "boundgate-debug.log"
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "debug-log").apply { isDaemon = true } }

    @Volatile private var dir: File? = null
    @Volatile var enabled = false
        private set
    // the worker's only
    private var out: FileOutputStream? = null
    private var size = 0L

    private val file get() = File(dir!!, NAME)
    private val older get() = File(dir!!, "$NAME.1")
    /** the file "Share debug log" hands out: the older part and the current one */
    val export get() = File(dir!!, "boundgate-debug-export.log")

    fun init(c: Context) {
        dir = File(c.filesDir, "debug")
        enabled = prefs(c).getBoolean("debug_log", false)
        if (enabled) {
            log("app", "process start")
            header(c)
        }
    }

    fun setEnabled(c: Context, on: Boolean) {
        prefs(c).edit().putBoolean("debug_log", on).apply()
        if (on && !enabled) {
            enabled = true
            log("app", "debug log on")
            header(c)
        } else if (!on && enabled) {
            log("app", "debug log off")
            enabled = false
        }
    }

    fun exists(): Boolean = dir?.let { File(it, NAME).exists() } == true

    /** One line; dropped when the log is off. May be called from any thread. */
    fun log(tag: String, line: String) {
        if (!enabled) return
        val at = "${Instant.now()} up=${SystemClock.uptimeMillis()} rt=${SystemClock.elapsedRealtime()}"
        worker.execute { write("$at [$tag] $line\n") }
    }

    /** Writes the export file (older part first) and returns it. Blocks. */
    fun snapshot(): File {
        val f = export
        val done: Future<*> = worker.submit {
            out?.flush()
            FileOutputStream(f).use { o ->
                for (part in listOf(older, file)) {
                    if (part.exists()) part.inputStream().use { it.copyTo(o) }
                }
            }
        }
        done.get()
        return f
    }

    fun clear() {
        worker.execute {
            out?.close()
            out = null
            size = 0
            older.delete()
            file.delete()
            export.delete()
        }
    }

    private fun header(c: Context) {
        val pm = c.getSystemService(PowerManager::class.java)
        val app = try { c.packageManager.getPackageInfo(c.packageName, 0).versionName } catch (e: Exception) { "?" }
        log("app", "version=$app core=${try { Core.version() } catch (e: Throwable) { "?" }} pid=${Process.myPid()} " +
            "device=${Build.MANUFACTURER} ${Build.MODEL} android=${Build.VERSION.RELEASE} sdk=${Build.VERSION.SDK_INT} " +
            "idle=${pm.isDeviceIdleMode} light_idle=${pm.isDeviceLightIdleMode} power_save=${pm.isPowerSaveMode} " +
            "battery_opt_ignored=${pm.isIgnoringBatteryOptimizations(c.packageName)}")
    }

    private fun prefs(c: Context) = c.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private fun write(line: String) {
        try {
            val o = out ?: open()
            val b = line.toByteArray()
            o.write(b)
            size += b.size
            if (size > MAX) {
                o.close()
                out = null
                older.delete()
                file.renameTo(older)
                size = 0
            }
        } catch (e: Exception) {
            Log.w(Node.TAG, "debug log: ${e.message}")
        }
    }

    private fun open(): FileOutputStream {
        dir!!.mkdirs()
        val f = file
        size = if (f.exists()) f.length() else 0
        return FileOutputStream(f, true).also { out = it }
    }
}
