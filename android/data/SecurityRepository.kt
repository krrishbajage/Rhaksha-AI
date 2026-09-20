package com.raksha.ai.data

import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import com.raksha.ai.network.SecurityApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class SecurityRepository(private val dao: SecurityEventDao, private val api: SecurityApi) {
    private val writeMutex = Mutex()
    val events: Flow<List<SecurityEvent>> = dao.observeAll().map { rows -> rows.map { it.toModel() } }

    suspend fun recoverInterrupted() = writeMutex.withLock {
        dao.failPending("Couldn't verify: analysis was interrupted")
        dao.applyRetention(System.currentTimeMillis() - RETENTION_MS)
    }

    /** Persist before networking. A cancellation deliberately leaves PENDING for startup recovery. */
    suspend fun capture(event: SecurityEvent) {
        writeMutex.withLock { persist(event.copy(analysisStatus = AnalysisStatus.PENDING, displayRisk = "PENDING")) }
        try {
            val report = api.analyzeEvent(event)
            writeMutex.withLock { persist(event.copy(analysisStatus = AnalysisStatus.COMPLETE, riskReport = report,
                displayRisk = report.risk_level, failureReason = null)) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            writeMutex.withLock { persist(event.copy(analysisStatus = AnalysisStatus.FAILED,
                displayRisk = "COULDN'T VERIFY", failureReason = boundedReason(error.message))) }
        }
    }

    suspend fun persist(event: SecurityEvent) {
        dao.upsert(SecurityEventEntity.from(event))
        dao.applyRetention(System.currentTimeMillis() - RETENTION_MS)
    }

    private fun boundedReason(reason: String?): String = (reason ?: "Couldn't verify").take(240)
    companion object { const val RETENTION_MS = 14L * 24 * 60 * 60 * 1000 }
}
