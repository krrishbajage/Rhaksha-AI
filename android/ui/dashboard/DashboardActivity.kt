package com.raksha.ai.ui.dashboard

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
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
import kotlinx.coroutines.launch

class DashboardActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyStateView: View
    private lateinit var accessBanner: View
    private lateinit var enableAccessButton: Button
    private val adapter = SecurityEventAdapter()
    private val viewModel: DashboardViewModel by viewModels {
        DashboardViewModelFactory((application as RakshaApplication).repository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dashboard)

        recyclerView = findViewById(R.id.eventsRecyclerView)
        emptyStateView = findViewById(R.id.emptyStateView)
        accessBanner = findViewById(R.id.accessBanner)
        enableAccessButton = findViewById(R.id.enableAccessButton)

        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
        recyclerView.itemAnimator = DefaultItemAnimator()
        recyclerView.setHasFixedSize(true)

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    adapter.submitList(state.events)
                    updateEmptyState()
                }
            }
        }

        enableAccessButton.setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
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
