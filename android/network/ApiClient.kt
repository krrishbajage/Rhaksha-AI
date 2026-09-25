package com.raksha.ai.network

import android.util.Log
import com.google.gson.GsonBuilder
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object ApiClient {

    private val httpLogger = HttpLoggingInterceptor { message ->
        Log.d("RAKSHA_HTTP", message)
    }.apply {
        // BASIC logs only request URLs and response status/timing, never
        // notification text, sender names, or JSON bodies.
        level = HttpLoggingInterceptor.Level.BASIC
    }

    private val okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        // A complete analysis performs message classification and explanation
        // generation.  Provider latency can exceed the original 15-second
        // read window, so keep the phone connected long enough to receive a
        // real report while retaining a bounded timeout.
        .readTimeout(75, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .addInterceptor(httpLogger)
        .build()

    private val gson = GsonBuilder()
        .serializeNulls()
        .create()

    val securityApi: SecurityApi = Retrofit.Builder()
        .baseUrl(NetworkConfig.BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create(gson))
        .build()
        .create(SecurityApi::class.java)
}
