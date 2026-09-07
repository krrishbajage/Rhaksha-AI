package com.raksha.ai.models

import android.os.Parcel
import android.os.Parcelable

data class RiskReport(
    val risk_score: Double,
    val risk_level: String,
    val scam_category: String,
    val explanation: String,
    val recommended_action: String
) : Parcelable {

    constructor(parcel: Parcel) : this(
        risk_score = parcel.readDouble(),
        risk_level = parcel.readString() ?: "",
        scam_category = parcel.readString() ?: "",
        explanation = parcel.readString() ?: "",
        recommended_action = parcel.readString() ?: ""
    )

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeDouble(risk_score)
        parcel.writeString(risk_level)
        parcel.writeString(scam_category)
        parcel.writeString(explanation)
        parcel.writeString(recommended_action)
    }

    override fun describeContents(): Int = 0

    companion object CREATOR : Parcelable.Creator<RiskReport> {
        override fun createFromParcel(parcel: Parcel): RiskReport = RiskReport(parcel)
        override fun newArray(size: Int): Array<RiskReport?> = arrayOfNulls(size)
    }
}
