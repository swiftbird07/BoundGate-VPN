package com.net407.boundgate

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.FileNotFoundException

/**
 * Hands the debug log's export file to the app the person shares it with
 * ("Share debug log"): the one file, read-only, and nothing else of the
 * app's storage. The app has no AndroidX, so no FileProvider; this is the
 * part of it that is needed. Not exported: only a grant that travels with
 * the share intent opens the URI.
 */
class LogProvider : ContentProvider() {

    override fun onCreate() = true

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (uri.authority != AUTHORITY || uri.path != "/$NAME" || mode != "r") throw FileNotFoundException(uri.toString())
        val f = DebugLog.export
        if (!f.exists()) throw FileNotFoundException(uri.toString())
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, args: Array<String>?, order: String?): Cursor {
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val c = MatrixCursor(cols, 1)
        if (uri.authority == AUTHORITY && uri.path == "/$NAME" && DebugLog.export.exists()) {
            c.addRow(cols.map { col ->
                when (col) {
                    OpenableColumns.DISPLAY_NAME -> NAME
                    OpenableColumns.SIZE -> DebugLog.export.length()
                    else -> null
                }
            })
        }
        return c
    }

    override fun getType(uri: Uri) = "text/plain"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<String>?) = 0

    companion object {
        const val AUTHORITY = "com.net407.boundgate.debuglog"
        const val NAME = "boundgate-debug.log"
        val uri: Uri = Uri.parse("content://$AUTHORITY/$NAME")
    }
}
