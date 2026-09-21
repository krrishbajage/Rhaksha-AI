package com.raksha.ai.data

import android.app.Application
import androidx.room.Room
import com.raksha.ai.network.ApiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class RakshaApplication : Application() {
    lateinit var repository: SecurityRepository
        private set
    lateinit var settingsStore: SettingsStore
        private set

    override fun onCreate() {
        super.onCreate()
        settingsStore = SettingsStore(this)
        val database = Room.databaseBuilder(this, RakshaDatabase::class.java, "raksha-events.db").build()
        repository = SecurityRepository(database.events(), ApiClient.securityApi)
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch { repository.recoverInterrupted() }
    }
}
