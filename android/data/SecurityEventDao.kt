package com.raksha.ai.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface SecurityEventDao {
    @Query("SELECT * FROM security_events ORDER BY createdAtMs DESC") fun observeAll(): Flow<List<SecurityEventEntity>>
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun upsert(event: SecurityEventEntity)
    @Query("UPDATE security_events SET status = 'FAILED', displayRisk = 'COULDN''T VERIFY', failureReason = :reason WHERE status = 'PENDING'") suspend fun failPending(reason: String)
    @Query("DELETE FROM security_events WHERE createdAtMs < :cutoff") suspend fun deleteOlderThan(cutoff: Long)
    @Query("DELETE FROM security_events WHERE eventId NOT IN (SELECT eventId FROM security_events ORDER BY createdAtMs DESC LIMIT 100)") suspend fun keepNewest100()
    @Transaction suspend fun applyRetention(cutoff: Long) { deleteOlderThan(cutoff); keepNewest100() }
}
