package com.raksha.ai.notification

import android.app.Notification
import android.app.Person
import android.os.Bundle
import android.service.notification.StatusBarNotification
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.util.UUID

object NotificationParser {
    const val MAX_MESSAGE_CODE_POINTS = 4_000

    fun parse(sbn: StatusBarNotification): SecurityEvent {
        val extras = sbn.notification.extras ?: Bundle()
        val latest = latestMessage(extras)
        val fallback = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
            .ifBlank { extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString().orEmpty() }
        val messageText = bounded(latest?.text?.takeIf { it.isNotBlank() } ?: fallback)
        val sender = bounded(latest?.sender ?: extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty())
            .ifBlank { null }

        // Normalizes Google Messages and Samsung Messages so LangGraph treats RCS as "sms"
        val sourceApp = when (sbn.packageName) {
            RakshaNotificationListenerService.WHATSAPP_PACKAGE -> "com.whatsapp"
            RakshaNotificationListenerService.GOOGLE_MESSAGES_PACKAGE,
            RakshaNotificationListenerService.SAMSUNG_MESSAGES_PACKAGE -> "sms"
            else -> sbn.packageName
        }

        return SecurityEvent(
            event_id = UUID.randomUUID().toString(),
            source_app = sourceApp,
            sender = sender,
            message_text = messageText,
            urls = UrlExtractor.extract(messageText),
            attachments = AttachmentDetector.detect(messageText),
            timestamp = Instant.ofEpochMilli(latest?.timestamp?.takeIf { it > 0 } ?: sbn.postTime).toString(),
            metadata = mapOf(
                "notification_key" to sbn.key,
                "post_time" to sbn.postTime,
                "channel" to if (sourceApp == "sms") "rcs" else "notification"
            ),
            analysisStatus = AnalysisStatus.PENDING,
            displayRisk = "PENDING"
        )
    }

    private data class ParsedMessage(val text: String, val sender: String?, val timestamp: Long)

    @Suppress("DEPRECATION")
    private fun latestMessage(extras: Bundle): ParsedMessage? {
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES) ?: return null
        for (index in messages.indices.reversed()) {
            val bundle = messages[index] as? Bundle ?: continue
            val text = bundle.getCharSequence("text")?.toString().orEmpty()
            if (text.isBlank()) continue
            val person = bundle.getParcelable<Person>("sender_person")
            return ParsedMessage(
                text,
                person?.name?.toString()
                    ?: bundle.getCharSequence("sender")?.toString()
                    ?: bundle.getCharSequence("sender_name")?.toString(),
                bundle.getLong("timestamp", 0L)
            )
        }
        return null
    }

    /** Code-point bounded, so a surrogate pair is never split. */
    internal fun bounded(value: String): String {
        if (value.codePointCount(0, value.length) <= MAX_MESSAGE_CODE_POINTS) return value
        return value.substring(0, value.offsetByCodePoints(0, MAX_MESSAGE_CODE_POINTS))
    }
}