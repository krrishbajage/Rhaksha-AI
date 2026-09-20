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

data class DashboardUiState(val events: List<SecurityEvent> = emptyList())
class DashboardViewModel(repository: SecurityRepository) : ViewModel() {
    val uiState: StateFlow<DashboardUiState> = repository.events.map(::DashboardUiState)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DashboardUiState())
}
class DashboardViewModelFactory(private val repository: SecurityRepository) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        @Suppress("UNCHECKED_CAST") return DashboardViewModel(repository) as T
    }
}
