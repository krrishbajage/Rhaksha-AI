package com.raksha.ai.notification

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.raksha.ai.models.SecurityEvent

class RakshaNotificationListenerService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        if (sbn.packageName != WHATSAPP_PACKAGE) return

        val event = NotificationParser.parse(sbn)
        logEvent(event)
        stubBackendCall(event)
        SecurityEventBus.post(event)
    }

    private fun logEvent(event: SecurityEvent) {
        Log.d(
            TAG,
            "Captured event ${event.event_id} from ${event.source_app}: " +
                "sender=${event.sender}, urls=${event.urls.size}, " +
                "attachments=${event.attachments.size}, text=${event.message_text.take(80)}"
        )
    }

    private fun stubBackendCall(event: SecurityEvent) {
        Log.d(
            TAG,
            "Backend stub: would POST ${event.event_id} to /api/events (not sent — backend not built yet)"
        )
    }

    companion object {
        private const val TAG = "RAKSHA"
        private const val WHATSAPP_PACKAGE = "com.whatsapp"
    }
}
