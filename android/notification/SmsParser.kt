package com.raksha.ai.notification

import android.content.Intent
import android.provider.Telephony
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.util.UUID
 
object SmsParser {
    fun parse(intent: Intent): SecurityEvent? {
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return null

        val firstMessage = messages.first()
        val messageText = NotificationParser.bounded(
            messages.joinToString(separator = "") { it.messageBody.orEmpty() }
        )
        val sender = NotificationParser.bounded(firstMessage.originatingAddress.orEmpty())
            .ifBlank { null }
        val timestampMillis = firstMessage.timestampMillis.takeIf { it > 0 }
            ?: System.currentTimeMillis()

        return SecurityEvent(
            event_id = UUID.randomUUID().toString(),
            source_app = "sms",
            sender = sender,
            message_text = messageText,
            urls = UrlExtractor.extract(messageText),
            attachments = AttachmentDetector.detect(messageText),
            timestamp = Instant.ofEpochMilli(timestampMillis).toString(),
            metadata = mapOf("channel" to "sms"),
            analysisStatus = AnalysisStatus.PENDING,
            displayRisk = "PENDING"
        )
    }
}