package com.raksha.ai.ui.history

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.raksha.ai.R
import com.raksha.ai.data.RakshaApplication
import com.raksha.ai.ui.dashboard.DashboardViewModel
import com.raksha.ai.ui.dashboard.DashboardViewModelFactory
import com.raksha.ai.ui.dashboard.SecurityEventAdapter
import com.raksha.ai.ui.detail.InvestigationDetailActivity
import kotlinx.coroutines.launch

class HistoryActivity : AppCompatActivity() {

    private lateinit var emptyStateView: View
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
        setContentView(R.layout.activity_history)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = getString(R.string.history_title)

        emptyStateView = findViewById(R.id.historyEmptyStateView)
        findViewById<RecyclerView>(R.id.historyRecyclerView).apply {
            layoutManager = LinearLayoutManager(this@HistoryActivity)
            adapter = this@HistoryActivity.adapter
            setHasFixedSize(true)
        }

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    adapter.submitList(state.events)
                    emptyStateView.visibility = if (state.events.isEmpty()) View.VISIBLE else View.GONE
                }
            }
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
