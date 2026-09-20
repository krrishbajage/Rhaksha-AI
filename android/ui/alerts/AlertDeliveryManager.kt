package com.raksha.ai.ui.alerts

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.raksha.ai.R
import com.raksha.ai.data.AlertMode
import com.raksha.ai.data.SettingsStore
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import com.raksha.ai.ui.detail.InvestigationDetailActivity
import kotlin.math.roundToInt

class AlertDeliveryManager(
    private val context: Context,
    private val settingsStore: SettingsStore
) {
    fun showAnalysisResult(event: SecurityEvent) {
        if (event.analysisStatus == AnalysisStatus.PENDING) return
        if (!canPostNotifications()) return

        ensureChannels()
        val mode = settingsStore.effectiveAlertMode()
        val intent = Intent(context, InvestigationDetailActivity::class.java)
            .putExtra(InvestigationDetailActivity.EXTRA_EVENT, event)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pendingIntent = PendingIntent.getActivity(
            context,
            event.event_id.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val publicNotification = NotificationCompat.Builder(context, channelId(mode))
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.public_alert_title))
            .setContentText(context.getString(R.string.public_alert_text))
            .setPriority(priority(mode))
            .build()

        val builder = NotificationCompat.Builder(context, channelId(mode))
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(alertTitle(event))
            .setContentText(alertBody(event))
            .setStyle(NotificationCompat.BigTextStyle().bigText(alertDetails(event)))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(priority(mode))
            .setVisibility(if (settingsStore.lockScreenPrivacy) NotificationCompat.VISIBILITY_PRIVATE else NotificationCompat.VISIBILITY_PUBLIC)
            .setPublicVersion(publicNotification)

        if (mode == AlertMode.SILENT) {
            builder.setSilent(true)
        }

        NotificationManagerCompat.from(context).notify(event.event_id.hashCode(), builder.build())
    }

    private fun alertTitle(event: SecurityEvent): String {
        if (event.analysisStatus == AnalysisStatus.FAILED) return context.getString(R.string.alert_failed_title)
        val level = event.riskReport?.risk_level ?: context.getString(R.string.risk_unknown)
        return context.getString(R.string.alert_result_title, level)
    }

    private fun alertBody(event: SecurityEvent): String {
        if (settingsStore.lockScreenPrivacy) return context.getString(R.string.public_alert_text)
        return event.sender?.let { context.getString(R.string.alert_sender_body, it) }
            ?: context.getString(R.string.alert_generic_body)
    }

    private fun alertDetails(event: SecurityEvent): String {
        if (event.analysisStatus == AnalysisStatus.FAILED) {
            return event.failureReason ?: context.getString(R.string.status_failed)
        }
        val report = event.riskReport ?: return context.getString(R.string.unavailable_value)
        return context.getString(
            R.string.alert_detail_text,
            report.risk_score.roundToInt(),
            report.scam_category.ifBlank { context.getString(R.string.unavailable_value) },
            report.recommended_action.ifBlank { context.getString(R.string.unavailable_value) }
        )
    }

    private fun ensureChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java)
        val loud = NotificationChannel(
            CHANNEL_LOUD,
            context.getString(R.string.channel_loud),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 240, 120, 240)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        val discreet = NotificationChannel(
            CHANNEL_DISCREET,
            context.getString(R.string.channel_discreet),
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            setSound(null, null)
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 80)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        val silent = NotificationChannel(
            CHANNEL_SILENT,
            context.getString(R.string.channel_silent),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            setSound(null, null)
            enableVibration(false)
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        manager.createNotificationChannels(listOf(loud, discreet, silent))
    }

    private fun canPostNotifications(): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }

    private fun channelId(mode: AlertMode): String = when (mode) {
        AlertMode.LOUD -> CHANNEL_LOUD
        AlertMode.DISCREET -> CHANNEL_DISCREET
        AlertMode.SILENT -> CHANNEL_SILENT
    }

    private fun priority(mode: AlertMode): Int = when (mode) {
        AlertMode.LOUD -> NotificationCompat.PRIORITY_HIGH
        AlertMode.DISCREET -> NotificationCompat.PRIORITY_DEFAULT
        AlertMode.SILENT -> NotificationCompat.PRIORITY_LOW
    }

    companion object {
        private const val CHANNEL_LOUD = "raksha_alerts_loud"
        private const val CHANNEL_DISCREET = "raksha_alerts_discreet"
        private const val CHANNEL_SILENT = "raksha_alerts_silent"
    }
}
