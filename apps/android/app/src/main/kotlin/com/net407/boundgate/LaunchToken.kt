package com.net407.boundgate

import android.content.Context
import android.content.Intent
import java.security.SecureRandom

/**
 * MainActivity is exported (it is the launcher), so any app on the phone can
 * start it with an explicit intent -- and with one of its actions, which
 * bring the tunnel up or push the user into a sign-in. The actions are for
 * the app's own tile and notification only: an intent they build carries
 * this token, which lives in the app's private preferences where no other
 * app reads it, and MainActivity honours an action only with it. A
 * PendingIntent of ours is immutable, so nobody rewrites its extras either.
 */
object LaunchToken {
    private const val PREFS = "launch"
    private const val KEY = "token"
    const val EXTRA = "com.net407.boundgate.LAUNCH_TOKEN"

    /** The token, made once per installation. */
    fun of(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY, null)?.let { return it }
        val b = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val token = b.joinToString("") { "%02x".format(it) }
        prefs.edit().putString(KEY, token).apply()
        return token
    }

    /** Marks an intent as the app's own. */
    fun stamp(context: Context, intent: Intent): Intent = intent.putExtra(EXTRA, of(context))

    /** Whether an intent that arrived carries the app's own token. */
    fun accepts(context: Context, intent: Intent?): Boolean =
        intent?.getStringExtra(EXTRA)?.let { it == of(context) } ?: false
}
