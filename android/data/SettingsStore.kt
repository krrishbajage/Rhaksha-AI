package com.raksha.ai.data

import android.content.Context
import java.time.LocalDateTime

enum class AlertMode {
    LOUD,
    DISCREET,
    SILENT
}

enum class MeetingMode {
    OFF,
    THIRTY_MINUTES,
    ONE_HOUR,
    TWO_HOURS,
    UNTIL_OFF
}

data class QuietHours(
    val enabled: Boolean,
    val daysMask: Int,
    val startMinutes: Int,
    val endMinutes: Int
)

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var alertMode: AlertMode
        get() = enumValue(KEY_ALERT_MODE, AlertMode.DISCREET)
        set(value) = prefs.edit().putString(KEY_ALERT_MODE, value.name).apply()

    var followSystemDnd: Boolean
        get() = prefs.getBoolean(KEY_FOLLOW_DND, true)
        set(value) = prefs.edit().putBoolean(KEY_FOLLOW_DND, value).apply()

    var lockScreenPrivacy: Boolean
        get() = prefs.getBoolean(KEY_LOCK_SCREEN_PRIVACY, true)
        set(value) = prefs.edit().putBoolean(KEY_LOCK_SCREEN_PRIVACY, value).apply()

    var onboardingComplete: Boolean
        get() = prefs.getBoolean(KEY_ONBOARDING_COMPLETE, false)
        set(value) = prefs.edit().putBoolean(KEY_ONBOARDING_COMPLETE, value).apply()

    fun meetingMode(): MeetingMode {
        val mode = enumValue(KEY_MEETING_MODE, MeetingMode.OFF)
        val endAt = prefs.getLong(KEY_MEETING_END_AT, 0L)
        if (mode != MeetingMode.OFF && endAt != UNTIL_OFF_END && endAt <= System.currentTimeMillis()) {
            setMeetingMode(MeetingMode.OFF)
            return MeetingMode.OFF
        }
        return mode
    }

    fun setMeetingMode(mode: MeetingMode) {
        val now = System.currentTimeMillis()
        val endAt = when (mode) {
            MeetingMode.OFF -> 0L
            MeetingMode.THIRTY_MINUTES -> now + 30L * 60_000L
            MeetingMode.ONE_HOUR -> now + 60L * 60_000L
            MeetingMode.TWO_HOURS -> now + 120L * 60_000L
            MeetingMode.UNTIL_OFF -> UNTIL_OFF_END
        }
        prefs.edit()
            .putString(KEY_MEETING_MODE, mode.name)
            .putLong(KEY_MEETING_END_AT, endAt)
            .apply()
    }

    fun quietHours(): QuietHours = QuietHours(
        enabled = prefs.getBoolean(KEY_QUIET_ENABLED, false),
        daysMask = prefs.getInt(KEY_QUIET_DAYS, ALL_DAYS_MASK),
        startMinutes = prefs.getInt(KEY_QUIET_START, 22 * 60),
        endMinutes = prefs.getInt(KEY_QUIET_END, 7 * 60)
    )

    fun setQuietHours(enabled: Boolean, daysMask: Int, startMinutes: Int, endMinutes: Int) {
        prefs.edit()
            .putBoolean(KEY_QUIET_ENABLED, enabled)
            .putInt(KEY_QUIET_DAYS, daysMask)
            .putInt(KEY_QUIET_START, startMinutes.coerceIn(0, MINUTES_PER_DAY - 1))
            .putInt(KEY_QUIET_END, endMinutes.coerceIn(0, MINUTES_PER_DAY - 1))
            .apply()
    }

    fun effectiveAlertMode(now: LocalDateTime = LocalDateTime.now()): AlertMode {
        if (meetingMode() != MeetingMode.OFF) return AlertMode.SILENT
        if (quietHours().isActive(now)) return AlertMode.SILENT
        return alertMode
    }

    private fun QuietHours.isActive(now: LocalDateTime): Boolean {
        if (!enabled) return false
        val dayBit = 1 shl (now.dayOfWeek.value - 1)
        if (daysMask and dayBit == 0) return false
        val minute = now.hour * 60 + now.minute
        return if (startMinutes <= endMinutes) {
            minute in startMinutes until endMinutes
        } else {
            minute >= startMinutes || minute < endMinutes
        }
    }

    private inline fun <reified T : Enum<T>> enumValue(key: String, default: T): T {
        val raw = prefs.getString(key, default.name) ?: default.name
        return runCatching { enumValueOf<T>(raw) }.getOrDefault(default)
    }

    companion object {
        private const val PREFS_NAME = "raksha_settings"
        private const val KEY_ALERT_MODE = "alert_mode"
        private const val KEY_FOLLOW_DND = "follow_dnd"
        private const val KEY_LOCK_SCREEN_PRIVACY = "lock_screen_privacy"
        private const val KEY_ONBOARDING_COMPLETE = "onboarding_complete"
        private const val KEY_MEETING_MODE = "meeting_mode"
        private const val KEY_MEETING_END_AT = "meeting_end_at"
        private const val KEY_QUIET_ENABLED = "quiet_enabled"
        private const val KEY_QUIET_DAYS = "quiet_days"
        private const val KEY_QUIET_START = "quiet_start"
        private const val KEY_QUIET_END = "quiet_end"
        private const val UNTIL_OFF_END = Long.MAX_VALUE
        const val MINUTES_PER_DAY = 24 * 60
        const val ALL_DAYS_MASK = 0b1111111
    }
}
