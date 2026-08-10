package com.raksha.ai.notification

import android.app.Notification
import android.os.Bundle
import android.service.notification.StatusBarNotification
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.util.UUID

object NotificationParser {

    fun parse(sbn: StatusBarNotification): SecurityEvent {
        val extras = sbn.notification.extras ?: Bundle()
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
        val infoText = extras.getCharSequence(Notification.EXTRA_INFO_TEXT)?.toString()

        val messageParts = mutableListOf<String>()
        var sender: String? = title

        @Suppress("DEPRECATION")
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        if (messages != null) {
            for (message in messages) {
                if (message !is Bundle) continue
                message.getCharSequence("text")?.toString()?.let { messageParts.add(it) }
                message.getCharSequence("sender")?.toString()?.let { sender = it }
                message.getCharSequence("sender_name")?.toString()?.let { sender = it }
            }
        }

        val messageText = when {
            !bigText.isNullOrBlank() -> bigText
            messageParts.isNotEmpty() -> messageParts.last()
            !text.isNullOrBlank() -> text
            else -> ""
        }

        val scanText = buildString {
            listOfNotNull(title, text, bigText, subText, infoText).forEach { appendLine(it) }
            messageParts.forEach { appendLine(it) }
        }

        val metadata = mutableMapOf<String, Any>(
            "notification_key" to sbn.key,
            "post_time" to sbn.postTime
        )
        if (!subText.isNullOrBlank()) metadata["sub_text"] = subText
        if (!infoText.isNullOrBlank()) metadata["info_text"] = infoText
        if (messageParts.size > 1) metadata["message_count"] = messageParts.size

        return SecurityEvent(
            event_id = UUID.randomUUID().toString(),
            source_app = sbn.packageName,
            sender = sender,
            message_text = messageText,
            urls = UrlExtractor.extract(scanText),
            attachments = AttachmentDetector.detect(scanText),
            timestamp = Instant.now().toString(),
            metadata = metadata
        )
    }
}
