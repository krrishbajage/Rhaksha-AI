package com.raksha.ai.ui.detail

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.raksha.ai.R
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlin.math.roundToInt

class InvestigationDetailActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_investigation_detail)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.investigation_title)

        val event = intent.getParcelableExtra<SecurityEvent>(EXTRA_EVENT)
        if (event == null) {
            finish()
            return
        }
        bind(event)
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun bind(event: SecurityEvent) {
        val report = event.riskReport
        text(R.id.detailSourceApp).text = event.source_app
        text(R.id.detailSender).text = event.sender ?: getString(R.string.unavailable_value)
        text(R.id.detailMessage).text = event.message_text.ifBlank { getString(R.string.no_message_text) }
        text(R.id.detailTimestamp).text = formatTimestamp(event.timestamp)
        text(R.id.detailUrls).text = event.urls.takeIf { it.isNotEmpty() }?.joinToString("\n")
            ?: getString(R.string.unavailable_value)
        text(R.id.detailAttachments).text = event.attachments.takeIf { it.isNotEmpty() }?.joinToString("\n")
            ?: getString(R.string.unavailable_value)
        text(R.id.detailStatus).text = statusText(event)
        text(R.id.detailRiskScore).text = report?.risk_score?.roundToInt()?.toString()
            ?: getString(R.string.unavailable_value)
        text(R.id.detailRiskLevel).text = report?.risk_level ?: getString(R.string.unavailable_value)
        text(R.id.detailCategory).text = report?.scam_category?.takeIf { it.isNotBlank() }?.replace('_', ' ')
            ?: getString(R.string.unavailable_value)
        text(R.id.detailExplanation).text = when {
            event.analysisStatus == AnalysisStatus.FAILED -> event.failureReason ?: getString(R.string.risk_failed)
            !report?.explanation.isNullOrBlank() -> report!!.explanation
            else -> getString(R.string.unavailable_value)
        }
        text(R.id.detailAction).text = report?.recommended_action?.takeIf { it.isNotBlank() }
            ?: getString(R.string.unavailable_value)
    }

    private fun statusText(event: SecurityEvent): String = when (event.analysisStatus) {
        AnalysisStatus.PENDING -> getString(R.string.status_pending)
        AnalysisStatus.COMPLETE -> getString(R.string.status_complete)
        AnalysisStatus.FAILED -> getString(R.string.status_failed)
    }

    private fun formatTimestamp(value: String): String = try {
        FORMATTER.format(Instant.parse(value).atZone(ZoneId.systemDefault()))
    } catch (_: Exception) {
        value
    }

    private fun text(id: Int): TextView = findViewById(id)

    companion object {
        const val EXTRA_EVENT = "com.raksha.ai.EXTRA_EVENT"
        private val FORMATTER = DateTimeFormatter.ofPattern("MMM d, yyyy h:mm a")
    }
}
