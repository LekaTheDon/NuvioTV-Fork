package com.nuvio.tv.core.player

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.OpenableColumns

/**
 * FEL fork: "Open with" for local video files (file managers, Kodi-style browsers, USB/NAS apps).
 * The player's DefaultDataSource already reads content:// and file:// URIs, so a local file only
 * needs a route into the player; the native FEL renderer then works exactly as for streams.
 */
data class LocalFilePlayback(
    val uri: String,
    val displayName: String,
    val sizeBytes: Long?
) {
    val isFileUri: Boolean get() = uri.startsWith("file:", ignoreCase = true)

    companion object {
        private val LOCAL_SCHEMES = setOf("content", "file")

        fun fromIntent(context: Context, intent: Intent?): LocalFilePlayback? {
            if (intent?.action != Intent.ACTION_VIEW) return null
            val uri = intent.data ?: return null
            if (uri.scheme?.lowercase() !in LOCAL_SCHEMES) return null
            var name: String? = null
            var size: Long? = null
            if (uri.scheme.equals("content", ignoreCase = true)) {
                runCatching {
                    context.contentResolver.query(
                        uri,
                        arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                        null,
                        null,
                        null
                    )?.use { cursor ->
                        if (cursor.moveToFirst()) {
                            val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                            if (nameIdx >= 0 && !cursor.isNull(nameIdx)) name = cursor.getString(nameIdx)
                            if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) size = cursor.getLong(sizeIdx)
                        }
                    }
                }
            } else {
                uri.path?.let { path -> java.io.File(path).takeIf { it.isFile }?.let { size = it.length() } }
            }
            val displayName = name?.takeIf(String::isNotBlank)
                ?: uri.lastPathSegment?.substringAfterLast('/')?.takeIf(String::isNotBlank)
                ?: "Local file"
            return LocalFilePlayback(uri.toString(), displayName, size?.takeIf { it > 0L })
        }

        /** Storage permission needed to read file:// paths (content:// URIs carry their own grant). */
        val readPermission: String
            get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Manifest.permission.READ_MEDIA_VIDEO
            } else {
                Manifest.permission.READ_EXTERNAL_STORAGE
            }

        fun hasReadPermission(context: Context): Boolean =
            context.checkSelfPermission(readPermission) == PackageManager.PERMISSION_GRANTED
    }
}
