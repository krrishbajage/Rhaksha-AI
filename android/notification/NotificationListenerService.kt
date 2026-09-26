package com.raksha.ai.notification

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.ui.alerts.AlertDeliveryManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.LinkedHashMap
import java.util.Locale
import java.security.MessageDigest

class RakshaNotificationListenerService : NotificationListenerService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val deduper = RecentNotificationDeduper()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        // Allow WhatsApp, Google Messages (RCS), and Samsung Messages
        if (sbn.packageName !in SUPPORTED_PACKAGES) return

        val skipReason = nonMessageSkipReason(sbn)
        if (skipReason != null) {
            Log.d(TAG, "Skipping unsupported notification from ${sbn.packageName}: $skipReason")
            return
        }

        val event = NotificationParser.parse(sbn)
        if (event.message_text.isBlank() && event.urls.isEmpty() && event.attachments.isEmpty()) {
            Log.d(TAG, "Skipping empty notification from ${sbn.packageName}")
            return
        }

        val fingerprints = dedupeFingerprints(sbn, event)
        if (deduper.alreadySeen(fingerprints)) {
            Log.d(
                TAG,
                "Skipping duplicate notification within ${RecentNotificationDeduper.WINDOW_MS}ms"
            )
            return
        }

        analyzeInBackground(event)
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun analyzeInBackground(event: SecurityEvent) {
        serviceScope.launch {
            try {
                val app = application as RakshaApplication
                val result = app.repository.capture(event)
                AlertDeliveryManager(applicationContext, app.settingsStore).showAnalysisResult(result)
            } catch (error: Exception) {
                Log.e(TAG, "Event analysis pipeline failed for id=${event.event_id}", error)
            }
        }
    }

    companion object {
        private const val TAG = "RAKSHA"
        const val WHATSAPP_PACKAGE = "com.whatsapp"
        const val GOOGLE_MESSAGES_PACKAGE = "com.google.android.apps.messaging"
        const val SAMSUNG_MESSAGES_PACKAGE = "com.samsung.android.messaging"

        val SUPPORTED_PACKAGES = setOf(
            WHATSAPP_PACKAGE,
            GOOGLE_MESSAGES_PACKAGE,
            SAMSUNG_MESSAGES_PACKAGE
        )

        // Matches background worker/sync foreground service alerts
        private val BACKGROUND_WORK_TEXT = Regex(
            """doing work in (the )?background|checking for (new )?messages|syncing|synchroniz|messages are doing work""",
            RegexOption.IGNORE_CASE
        )

        private val CALL_TEXT = Regex(
            """
            incoming (group )?(voice|video) call|
            ongoing (group )?(voice|video) call|
            missed (group )?(voice|video) call|
            whatsapp (voice|video )?call|
            \bis calling\b|
            \bringing\b|
            \bcalling[.…]*$
            """.trimIndent().replace("\n", ""),
            RegexOption.IGNORE_CASE
        )
        private val SUMMARY_TEXT = Regex(
            """\b\d+\s+(new\s+)?messages?\b""",
            RegexOption.IGNORE_CASE
        )
        private val SYSTEM_EVENT_TEXT = Regex(
            """created (this )?group|added you|removed you|left the group|you're now an admin|changed the group""",
            RegexOption.IGNORE_CASE
        )
        private val CALL_ACTION = Regex(
            """^(answer|decline|reject|hang up|hangup)$""",
            RegexOption.IGNORE_CASE
        )

        internal fun nonMessageSkipReason(sbn: StatusBarNotification): String? {
            val notification = sbn.notification
            val extras = notification.extras
            val category = notification.category
            val channelId = notification.channelId.orEmpty()
            val tag = sbn.tag.orEmpty()
            val template = extras.getString(Notification.EXTRA_TEMPLATE).orEmpty()
            val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
            val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
            val summaryText = extras.getCharSequence(Notification.EXTRA_SUMMARY_TEXT)?.toString().orEmpty()
            val combined = "$title $text $summaryText"

            // 1. Filter ongoing foreground services & persistent system alerts
            if (sbn.isOngoing || (notification.flags and Notification.FLAG_ONGOING_EVENT != 0)) {
                return "ongoing service notification"
            }
            if (!sbn.isClearable) {
                return "non-clearable notification"
            }

            // 2. Filter non-message categories (service, progress, status, system)
            if (category == Notification.CATEGORY_SERVICE ||
                category == Notification.CATEGORY_PROGRESS ||
                category == Notification.CATEGORY_STATUS ||
                category == Notification.CATEGORY_SYSTEM
            ) {
                return "service/progress category ($category)"
            }

            // 3. Filter channels dedicated to background work or sync
            if (channelId.contains("foreground", ignoreCase = true) ||
                channelId.contains("background", ignoreCase = true) ||
                channelId.contains("sync", ignoreCase = true)
            ) {
                return "background/sync channel ($channelId)"
            }

            // 4. Text match for background worker strings
            if (BACKGROUND_WORK_TEXT.containsMatchIn(combined)) {
                return "background work text"
            }

            // 5. Call & incoming call UI checks
            if (category == Notification.CATEGORY_CALL || category == Notification.CATEGORY_MISSED_CALL) {
                return "category=$category"
            }
            if (notification.fullScreenIntent != null) {
                return "full-screen intent (incoming call UI)"
            }
            if (template.contains("CallStyle", ignoreCase = true)) {
                return "template=CallStyle"
            }
            if (hasCallAction(notification)) {
                return "call action buttons (Answer/Decline)"
            }

            // 6. Group summaries & system event checks
            if (notification.flags and Notification.FLAG_GROUP_SUMMARY != 0) {
                return "group summary flag"
            }
            if (channelId.contains("call", ignoreCase = true) ||
                channelId.contains("voip", ignoreCase = true) ||
                channelId.contains("ringing", ignoreCase = true)
            ) {
                return "channelId=$channelId"
            }
            if (tag.contains("call", ignoreCase = true) || tag.contains("voip", ignoreCase = true)) {
                return "tag=$tag"
            }
            if (CALL_TEXT.containsMatchIn(combined)) {
                return "call-like text"
            }
            if (SUMMARY_TEXT.containsMatchIn(combined) || SUMMARY_TEXT.containsMatchIn(summaryText)) {
                return "summary notification"
            }
            if (SYSTEM_EVENT_TEXT.containsMatchIn(combined)) {
                return "non-message system event"
            }

            return null
        }

        internal fun lastStableMessage(sbn: StatusBarNotification): String {
            val extras = sbn.notification.extras
            @Suppress("DEPRECATION")
            val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            if (messages != null) {
                for (index in messages.indices.reversed()) {
                    val message = messages[index] as? android.os.Bundle ?: continue
                    val body = message.getCharSequence("text")?.toString()?.trim().orEmpty()
                    if (body.isNotEmpty()) return body
                }
            }
            return extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim().orEmpty()
        }

        internal fun dedupeFingerprints(sbn: StatusBarNotification, event: SecurityEvent): List<String> {
            val lastMessage = lastStableMessage(sbn).ifBlank { event.message_text }
            val sender = event.sender.orEmpty().trim().lowercase(Locale.US)
            val text = lastMessage.trim().lowercase(Locale.US)
            return listOf(
                "id:${sbn.id}|msg:$text",
                "msg:$sender|$text"
            ).map(::sha256)
        }

        private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

        private fun hasCallAction(notification: Notification): Boolean {
            val actions = notification.actions ?: return false
            return actions.any { action ->
                CALL_ACTION.containsMatchIn(action.title?.toString()?.trim().orEmpty())
            }
        }
    }
}

internal class RecentNotificationDeduper(
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    private val seen = object : LinkedHashMap<String, Long>(MAX_ENTRIES, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > MAX_ENTRIES
        }
    }

    @Synchronized
    fun alreadySeen(fingerprints: Collection<String>): Boolean {
        val now = nowMs()
        val iterator = seen.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value > WINDOW_MS) iterator.remove()
        }
        val duplicate = fingerprints.any { fingerprint ->
            val lastSeen = seen[fingerprint]
            lastSeen != null && now - lastSeen <= WINDOW_MS
        }
        if (duplicate) return true
        fingerprints.forEach { fingerprint -> seen[fingerprint] = now }
        return false
    }

    companion object {
        const val WINDOW_MS = 15_000L
        private const val MAX_ENTRIES = 100
    }
}