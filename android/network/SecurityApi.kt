package com.raksha.ai.network

import com.raksha.ai.models.RiskReport
import com.raksha.ai.models.SecurityEvent
import com.raksha.ai.models.AnalysisStatus
import retrofit2.http.Body
import retrofit2.http.POST

data class GoogleAuthExchangeRequest(val auth_code: String)

data class GoogleAuthExchangeResponse(val connected: String)

data class EmailSyncRequest(val user_email: String)

data class SecurityEventDto(
    val event_id: String,
    val source_app: String,
    val sender: String? = null,
    val message_text: String = "",
    val urls: List<String> = emptyList(),
    val attachments: List<String> = emptyList(),
    val timestamp: String,
    val metadata: Map<String, Any> = emptyMap()
) {
    fun toModel(): SecurityEvent = SecurityEvent(
        event_id = event_id,
        source_app = source_app,
        sender = sender,
        message_text = message_text,
        urls = urls,
        attachments = attachments,
        timestamp = timestamp,
        metadata = metadata
    )
}

data class SyncedEmailRiskReportDto(
    val risk_score: Double,
    val risk_level: String,
    val scam_category: String? = null,
    val explanation: String? = null,
    val recommended_action: String? = null,
    val summary: String? = null,
    val evidence: List<Any>? = null
) {
    fun toModel(): RiskReport {
        val explanationText = listOfNotNull(
            explanation?.takeIf { it.isNotBlank() },
            summary?.takeIf { it.isNotBlank() },
            evidence?.joinToString("\n") { "- $it" }?.takeIf { it.isNotBlank() }
        ).joinToString("\n")
        return RiskReport(
            risk_score = risk_score,
            risk_level = risk_level,
            scam_category = scam_category.orEmpty(),
            explanation = explanationText,
            recommended_action = recommended_action.orEmpty()
        )
    }
}

data class SyncedEmailReport(
    val gmail_message_id: String,
    val event: SecurityEventDto,
    val risk_report: SyncedEmailRiskReportDto
)

interface SecurityApi {
    @POST("api/events/analyze")
    suspend fun analyzeEvent(@Body event: SecurityEvent): RiskReport

    @POST("api/auth/google/exchange")
    suspend fun exchange(@Body body: GoogleAuthExchangeRequest): GoogleAuthExchangeResponse

    @POST("api/email/sync")
    suspend fun sync(@Body body: EmailSyncRequest): List<SyncedEmailReport>
}
