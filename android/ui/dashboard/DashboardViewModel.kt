package com.raksha.ai.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.raksha.ai.data.SecurityRepository
import com.raksha.ai.models.SecurityEvent
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

data class DashboardUiState(
    val events: List<SecurityEvent> = emptyList(),
    val totalCount: Int = 0,
    val pendingCount: Int = 0,
    val completeCount: Int = 0,
    val failedCount: Int = 0,
    val highRiskCount: Int = 0
)

class DashboardViewModel(repository: SecurityRepository) : ViewModel() {
    val uiState: StateFlow<DashboardUiState> = repository.events.map { events ->
        DashboardUiState(
            events = events,
            totalCount = events.size,
            pendingCount = events.count { it.analysisStatus == com.raksha.ai.models.AnalysisStatus.PENDING },
            completeCount = events.count { it.analysisStatus == com.raksha.ai.models.AnalysisStatus.COMPLETE },
            failedCount = events.count { it.analysisStatus == com.raksha.ai.models.AnalysisStatus.FAILED },
            highRiskCount = events.count { it.isHighRisk() }
        )
    }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DashboardUiState())
}

fun SecurityEvent.isHighRisk(): Boolean {
    if (analysisStatus != com.raksha.ai.models.AnalysisStatus.COMPLETE) return false
    return when (riskReport?.risk_level?.lowercase()) {
        "high", "critical", "danger" -> true
        else -> false
    }
}

class DashboardViewModelFactory(private val repository: SecurityRepository) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        @Suppress("UNCHECKED_CAST") return DashboardViewModel(repository) as T
    }
}
