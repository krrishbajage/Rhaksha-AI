package com.raksha.ai.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.RiskReport
import com.raksha.ai.models.SecurityEvent

@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey val eventId: String,
    val sourceApp: String,
    val sender: String?,
    val messageText: String,
    val urlsJson: String,
    val attachmentsJson: String,
    val eventTimestamp: String,
    val createdAtMs: Long,
    val status: String,
    val riskScore: Double?,
    val riskLevel: String?,
    val scamCategory: String?,
    val explanation: String?,
    val recommendedAction: String?,
    val displayRisk: String,
    val failureReason: String?
) {
    fun toModel(): SecurityEvent = SecurityEvent(eventId, sourceApp, sender, messageText,
        gson.fromJson(urlsJson, stringListType), gson.fromJson(attachmentsJson, stringListType),
        eventTimestamp, analysisStatus = AnalysisStatus.valueOf(status), riskReport = riskScore?.let {
            RiskReport(it, riskLevel.orEmpty(), scamCategory.orEmpty(), explanation.orEmpty(), recommendedAction.orEmpty())
        }, displayRisk = displayRisk, failureReason = failureReason)

    companion object {
        private val gson = Gson()
        private val stringListType = object : TypeToken<List<String>>() {}.type
        fun from(event: SecurityEvent, now: Long = System.currentTimeMillis()) = SecurityEventEntity(
            event.event_id, event.source_app, event.sender, event.message_text,
            gson.toJson(event.urls), gson.toJson(event.attachments), event.timestamp, now,
            event.analysisStatus.name, event.riskReport?.risk_score, event.riskReport?.risk_level,
            event.riskReport?.scam_category, event.riskReport?.explanation, event.riskReport?.recommended_action,
            event.displayRisk, event.failureReason
        )
    }
}
