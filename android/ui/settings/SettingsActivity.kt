package com.raksha.ai.ui.settings

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.Spinner
import android.widget.Switch
import androidx.appcompat.app.AppCompatActivity
import com.raksha.ai.R
import com.raksha.ai.data.AlertMode
import com.raksha.ai.data.MeetingMode
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.data.SettingsStore

class SettingsActivity : AppCompatActivity() {
    private lateinit var settingsStore: SettingsStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.settings_title)
        settingsStore = (application as RakshaApplication).settingsStore

        bindAlertMode()
        bindMeetingMode()
        bindQuietHours()
        bindToggles()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun bindAlertMode() {
        val spinner = findViewById<Spinner>(R.id.alertModeSpinner)
        val values = AlertMode.values()
        spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, values.map { it.displayName() })
        spinner.setSelection(values.indexOf(settingsStore.alertMode).coerceAtLeast(0))
        findViewById<Button>(R.id.saveAlertModeButton).setOnClickListener {
            settingsStore.alertMode = values[spinner.selectedItemPosition]
        }
    }

    private fun bindMeetingMode() {
        val spinner = findViewById<Spinner>(R.id.meetingModeSpinner)
        val values = MeetingMode.values()
        spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, values.map { meetingModeLabel(it) })
        spinner.setSelection(values.indexOf(settingsStore.meetingMode()).coerceAtLeast(0))
        findViewById<Button>(R.id.saveMeetingModeButton).setOnClickListener {
            settingsStore.setMeetingMode(values[spinner.selectedItemPosition])
        }
    }

    private fun bindQuietHours() {
        val quietHours = settingsStore.quietHours()
        val enabledSwitch = findViewById<Switch>(R.id.quietHoursSwitch)
        val startSpinner = findViewById<Spinner>(R.id.quietStartSpinner)
        val endSpinner = findViewById<Spinner>(R.id.quietEndSpinner)
        val hourLabels = (0..23).map { "%02d:00".format(it) }
        startSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, hourLabels)
        endSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, hourLabels)
        enabledSwitch.isChecked = quietHours.enabled
        startSpinner.setSelection(quietHours.startMinutes / 60)
        endSpinner.setSelection(quietHours.endMinutes / 60)

        dayCheckBoxes().forEachIndexed { index, checkBox ->
            checkBox.isChecked = quietHours.daysMask and (1 shl index) != 0
        }
        findViewById<Button>(R.id.saveQuietHoursButton).setOnClickListener {
            val daysMask = dayCheckBoxes().foldIndexed(0) { index, mask, checkBox ->
                if (checkBox.isChecked) mask or (1 shl index) else mask
            }
            settingsStore.setQuietHours(
                enabled = enabledSwitch.isChecked,
                daysMask = daysMask,
                startMinutes = startSpinner.selectedItemPosition * 60,
                endMinutes = endSpinner.selectedItemPosition * 60
            )
        }
    }

    private fun bindToggles() {
        findViewById<Switch>(R.id.followDndSwitch).apply {
            isChecked = settingsStore.followSystemDnd
            setOnCheckedChangeListener { _, checked -> settingsStore.followSystemDnd = checked }
        }
        findViewById<Switch>(R.id.lockPrivacySwitch).apply {
            isChecked = settingsStore.lockScreenPrivacy
            setOnCheckedChangeListener { _, checked -> settingsStore.lockScreenPrivacy = checked }
        }
    }

    private fun dayCheckBoxes(): List<CheckBox> = listOf(
        findViewById(R.id.dayMonday),
        findViewById(R.id.dayTuesday),
        findViewById(R.id.dayWednesday),
        findViewById(R.id.dayThursday),
        findViewById(R.id.dayFriday),
        findViewById(R.id.daySaturday),
        findViewById(R.id.daySunday)
    )

    private fun AlertMode.displayName(): String = when (this) {
        AlertMode.LOUD -> getString(R.string.alert_mode_loud)
        AlertMode.DISCREET -> getString(R.string.alert_mode_discreet)
        AlertMode.SILENT -> getString(R.string.alert_mode_silent)
    }

    private fun meetingModeLabel(mode: MeetingMode): String = when (mode) {
        MeetingMode.OFF -> getString(R.string.meeting_mode_off)
        MeetingMode.THIRTY_MINUTES -> getString(R.string.meeting_mode_30m)
        MeetingMode.ONE_HOUR -> getString(R.string.meeting_mode_1h)
        MeetingMode.TWO_HOURS -> getString(R.string.meeting_mode_2h)
        MeetingMode.UNTIL_OFF -> getString(R.string.meeting_mode_until_off)
    }
}
