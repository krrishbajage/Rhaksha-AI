package com.raksha.ai.ui.settings

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.Spinner
import android.widget.Switch
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.Scope
import com.raksha.ai.R
import com.raksha.ai.data.AlertMode
import com.raksha.ai.data.MeetingMode
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.data.SettingsStore
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.network.ApiClient
import com.raksha.ai.network.EmailSyncRequest
import com.raksha.ai.network.GoogleAuthExchangeRequest
import com.raksha.ai.network.NetworkConfig
import kotlinx.coroutines.launch
import retrofit2.HttpException
import java.io.IOException

class SettingsActivity : AppCompatActivity() {
    private lateinit var settingsStore: SettingsStore
    private lateinit var connectGmailButton: Button
    private lateinit var syncEmailButton: Button

    private val googleSignInLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        try {
            val account = task.getResult(ApiException::class.java)
            val authCode = account.serverAuthCode
            if (authCode.isNullOrBlank()) {
                showError(getString(R.string.gmail_missing_auth_code))
                return@registerForActivityResult
            }
            exchangeAuthCode(authCode)
        } catch (error: ApiException) {
            if (error.statusCode == GoogleSignInStatusCodes.SIGN_IN_CANCELLED) {
                showError(getString(R.string.gmail_signin_cancelled))
            } else {
                val detail = error.statusMessage ?: error.message ?: error.statusCode.toString()
                showError(getString(R.string.gmail_signin_failed, detail))
            }
        } catch (error: Exception) {
            showError(getString(R.string.gmail_signin_failed, error.message ?: error.toString()))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.settings_title)
        settingsStore = (application as RakshaApplication).settingsStore

        connectGmailButton = findViewById(R.id.connectGmailButton)
        syncEmailButton = findViewById(R.id.syncEmailButton)
        connectGmailButton.setOnClickListener { startGmailConnect() }
        syncEmailButton.setOnClickListener { syncEmailNow() }
        refreshGmailUi()

        bindAlertMode()
        bindMeetingMode()
        bindQuietHours()
        bindToggles()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun startGmailConnect() {
        if (NetworkConfig.GOOGLE_WEB_CLIENT_ID.isBlank()) {
            showError(getString(R.string.gmail_missing_web_client_id))
            return
        }
        val options = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestServerAuthCode(NetworkConfig.GOOGLE_WEB_CLIENT_ID, true)
            .requestScopes(Scope(GMAIL_READONLY_SCOPE))
            .build()
        val client = GoogleSignIn.getClient(this, options)
        googleSignInLauncher.launch(client.signInIntent)
    }

    private fun exchangeAuthCode(authCode: String) {
        lifecycleScope.launch {
            try {
                val response = ApiClient.securityApi.exchange(GoogleAuthExchangeRequest(authCode))
                val email = response.connected.trim()
                if (email.isEmpty()) {
                    showError(getString(R.string.gmail_exchange_failed, "empty email from backend"))
                    return@launch
                }
                settingsStore.connectedGmailEmail = email
                refreshGmailUi()
                Toast.makeText(
                    this@SettingsActivity,
                    getString(R.string.gmail_connected_toast, email),
                    Toast.LENGTH_LONG
                ).show()
            } catch (error: Exception) {
                showError(getString(R.string.gmail_exchange_failed, describeFailure(error)))
            }
        }
    }

    private fun syncEmailNow() {
        val email = settingsStore.connectedGmailEmail
        if (email.isNullOrBlank()) {
            showError(getString(R.string.gmail_sync_failed, "no Gmail account connected"))
            return
        }
        syncEmailButton.isEnabled = false
        syncEmailButton.text = getString(R.string.sync_email_loading)
        lifecycleScope.launch {
            try {
                val reports = ApiClient.securityApi.sync(EmailSyncRequest(email))
                val repository = (application as RakshaApplication).repository
                reports.forEach { synced ->
                    val riskReport = synced.risk_report.toModel()
                    repository.persist(
                        synced.event.toModel().copy(
                            analysisStatus = AnalysisStatus.COMPLETE,
                            riskReport = riskReport,
                            displayRisk = riskReport.risk_level,
                            failureReason = null
                        )
                    )
                }
                val message = if (reports.isEmpty()) {
                    getString(R.string.gmail_sync_none)
                } else {
                    getString(R.string.gmail_sync_count, reports.size)
                }
                Toast.makeText(this@SettingsActivity, message, Toast.LENGTH_LONG).show()
            } catch (error: Exception) {
                showError(getString(R.string.gmail_sync_failed, describeFailure(error)))
            } finally {
                syncEmailButton.isEnabled = true
                refreshGmailUi()
            }
        }
    }

    private fun refreshGmailUi() {
        val email = settingsStore.connectedGmailEmail
        if (email.isNullOrBlank()) {
            connectGmailButton.setText(R.string.connect_gmail)
            syncEmailButton.visibility = View.GONE
        } else {
            connectGmailButton.text = getString(R.string.connected_as, email)
            syncEmailButton.visibility = View.VISIBLE
            if (syncEmailButton.isEnabled) {
                syncEmailButton.setText(R.string.sync_email_now)
            }
        }
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun describeFailure(error: Throwable): String = when (error) {
        is HttpException -> error.response()?.errorBody()?.string()?.takeIf { it.isNotBlank() }
            ?: "HTTP ${error.code()}"
        is IOException -> "network error"
        else -> error.message ?: error.toString()
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

    companion object {
        private const val GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    }
}
