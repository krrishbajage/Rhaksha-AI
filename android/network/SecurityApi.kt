package com.raksha.ai.network

import com.raksha.ai.models.RiskReport
import com.raksha.ai.models.SecurityEvent
import retrofit2.http.Body
import retrofit2.http.POST

interface SecurityApi {
    @POST("api/events/analyze")
    suspend fun analyzeEvent(@Body event: SecurityEvent): RiskReport
}
