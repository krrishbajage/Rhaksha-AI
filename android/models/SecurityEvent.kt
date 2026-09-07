package com.raksha.ai.models

import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable

enum class AnalysisStatus {
    PENDING,
    COMPLETE,
    FAILED
}

data class SecurityEvent(
    val event_id: String,
    val source_app: String,
    val sender: String?,
    val message_text: String,
    val urls: List<String>,
    val attachments: List<String>,
    val timestamp: String,
    val metadata: Map<String, Any> = emptyMap(),
    @Transient val analysisStatus: AnalysisStatus = AnalysisStatus.PENDING,
    @Transient val riskReport: RiskReport? = null
) : Parcelable {

    constructor(parcel: Parcel) : this(
        event_id = parcel.readString() ?: "",
        source_app = parcel.readString() ?: "",
        sender = parcel.readString(),
        message_text = parcel.readString() ?: "",
        urls = parcel.createStringArrayList() ?: emptyList(),
        attachments = parcel.createStringArrayList() ?: emptyList(),
        timestamp = parcel.readString() ?: "",
        metadata = bundleToMap(parcel.readBundle(SecurityEvent::class.java.classLoader)),
        analysisStatus = AnalysisStatus.valueOf(
            parcel.readString() ?: AnalysisStatus.PENDING.name
        ),
        riskReport = parcel.readParcelable(RiskReport::class.java.classLoader)
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(event_id)
        parcel.writeString(source_app)
        parcel.writeString(sender)
        parcel.writeString(message_text)
        parcel.writeStringList(ArrayList(urls))
        parcel.writeStringList(ArrayList(attachments))
        parcel.writeString(timestamp)
        parcel.writeBundle(mapToBundle(metadata))
        parcel.writeString(analysisStatus.name)
        parcel.writeParcelable(riskReport, flags)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<SecurityEvent> {
        override fun createFromParcel(parcel: Parcel): SecurityEvent = SecurityEvent(parcel)

        override fun newArray(size: Int): Array<SecurityEvent?> = arrayOfNulls(size)

        private fun mapToBundle(map: Map<String, Any>): Bundle {
            val bundle = Bundle()
            map.forEach { (key, value) ->
                when (value) {
                    is String -> bundle.putString(key, value)
                    is Int -> bundle.putInt(key, value)
                    is Long -> bundle.putLong(key, value)
                    is Boolean -> bundle.putBoolean(key, value)
                    is Double -> bundle.putDouble(key, value)
                    else -> bundle.putString(key, value.toString())
                }
            }
            return bundle
        }

        private fun bundleToMap(bundle: Bundle?): Map<String, Any> {
            if (bundle == null) return emptyMap()
            val map = mutableMapOf<String, Any>()
            bundle.keySet().forEach { key ->
                map[key] = bundle.get(key)?.toString() ?: ""
            }
            return map
        }
    }
}
