package com.raksha.ai.notification

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import com.raksha.ai.network.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class RakshaNotificationListenerService : NotificationListenerService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName != WHATSAPP_PACKAGE) return

        val event = NotificationParser.parse(sbn)
        logEvent(event)
        SecurityEventBus.upsert(event)
        analyzeInBackground(event)
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun analyzeInBackground(event: SecurityEvent) {
        serviceScope.launch {
            try {
                val report = ApiClient.securityApi.analyzeEvent(event)
                Log.d(TAG, "Analyze success for ${event.event_id}: ${report.risk_level} ${report.risk_score}")
                SecurityEventBus.upsert(
                    event.copy(
                        analysisStatus = AnalysisStatus.COMPLETE,
                        riskReport = report
                    )
                )
            } catch (error: Exception) {
                Log.e(TAG, "Analyze failed for ${event.event_id}: ${error.message}", error)
                SecurityEventBus.upsert(
                    event.copy(analysisStatus = AnalysisStatus.FAILED)
                )
            }
        }
    }

    private fun logEvent(event: SecurityEvent) {
        Log.d(
            TAG,
            "Captured event ${event.event_id} from ${event.source_app}: " +
                "sender=${event.sender}, urls=${event.urls.size}, " +
                "attachments=${event.attachments.size}, text=${event.message_text.take(80)}"
        )
    }

    companion object {
        private const val TAG = "RAKSHA"
        private const val WHATSAPP_PACKAGE = "com.whatsapp"
    }
}
