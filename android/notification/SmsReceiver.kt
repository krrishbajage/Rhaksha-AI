package com.raksha.ai.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.ui.alerts.AlertDeliveryManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob 
import kotlinx.coroutines.launch

class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val event = SmsParser.parse(intent) ?: return
        if (event.message_text.isBlank() && event.urls.isEmpty() && event.attachments.isEmpty()) return

        val appContext = context.applicationContext
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                val app = appContext as RakshaApplication
                val result = app.repository.capture(event)
                AlertDeliveryManager(appContext, app.settingsStore).showAnalysisResult(result)
            } catch (error: Exception) {
                Log.e(TAG, "SMS event analysis pipeline failed for id=${event.event_id}", error)
            } finally {
                pendingResult.finish()
            }
        }
    }

    companion object {
        private const val TAG = "RAKSHA"
    }
}