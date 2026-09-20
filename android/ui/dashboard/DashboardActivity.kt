package com.raksha.ai.ui.dashboard

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DefaultItemAnimator
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.raksha.ai.R
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.notification.RakshaNotificationListenerService
import com.raksha.ai.ui.detail.InvestigationDetailActivity
import com.raksha.ai.ui.history.HistoryActivity
import com.raksha.ai.ui.onboarding.OnboardingActivity
import com.raksha.ai.ui.settings.SettingsActivity
import kotlinx.coroutines.launch

class DashboardActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateView: View
    private lateinit var accessBanner: View
    private lateinit var enableAccessButton: Button
    private lateinit var protectionStatusText: TextView
    private lateinit var totalCountText: TextView
    private lateinit var pendingCountText: TextView
    private lateinit var highRiskCountText: TextView
    private lateinit var failedCountText: TextView
    private lateinit var historyButton: Button
    private lateinit var settingsButton: Button
    private val adapter = SecurityEventAdapter { event ->
        startActivity(
            Intent(this, InvestigationDetailActivity::class.java)
                .putExtra(InvestigationDetailActivity.EXTRA_EVENT, event)
        )
    }
    private val viewModel: DashboardViewModel by viewModels {
        DashboardViewModelFactory((application as RakshaApplication).repository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as RakshaApplication
        if (!app.settingsStore.onboardingComplete) {
            startActivity(Intent(this, OnboardingActivity::class.java))
        }
        setContentView(R.layout.activity_dashboard)

        recyclerView = findViewById(R.id.eventsRecyclerView)
        emptyStateView = findViewById(R.id.emptyStateView)
        accessBanner = findViewById(R.id.accessBanner)
        enableAccessButton = findViewById(R.id.enableAccessButton)
        protectionStatusText = findViewById(R.id.protectionStatusText)
        totalCountText = findViewById(R.id.totalCountText)
        pendingCountText = findViewById(R.id.pendingCountText)
        highRiskCountText = findViewById(R.id.highRiskCountText)
        failedCountText = findViewById(R.id.failedCountText)
        historyButton = findViewById(R.id.historyButton)
        settingsButton = findViewById(R.id.settingsButton)

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
        recyclerView.itemAnimator = DefaultItemAnimator()
        recyclerView.setHasFixedSize(true)

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    adapter.submitList(state.events)
                    totalCountText.text = state.totalCount.toString()
                    pendingCountText.text = state.pendingCount.toString()
                    highRiskCountText.text = state.highRiskCount.toString()
                    failedCountText.text = state.failedCount.toString()
                    updateEmptyState()
                }
            }
        }

        enableAccessButton.setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
        historyButton.setOnClickListener {
            startActivity(Intent(this, HistoryActivity::class.java))
        }
        settingsButton.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    override fun onStart() {
        super.onStart()
        updateAccessBanner()
        updateEmptyState()
    }

    override fun onStop() {
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        updateAccessBanner()
    }

    private fun updateEmptyState() {
        emptyStateView.visibility = if (adapter.itemCount == 0) View.VISIBLE else View.GONE
    }

    private fun updateAccessBanner() {
        val enabled = isNotificationListenerEnabled()
        accessBanner.visibility = if (enabled) View.GONE else View.VISIBLE
        protectionStatusText.text = if (enabled) {
            getString(R.string.protection_active)
        } else {
            getString(R.string.protection_needs_access)
        }
    }

    private fun isNotificationListenerEnabled(): Boolean {
        val component = ComponentName(this, RakshaNotificationListenerService::class.java)
        val enabledListeners = Settings.Secure.getString(
            contentResolver,
            "enabled_notification_listeners"
        ) ?: return false
        return enabledListeners.contains(component.flattenToString())
    }
}
