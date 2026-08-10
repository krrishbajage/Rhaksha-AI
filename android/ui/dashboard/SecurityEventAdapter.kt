package com.raksha.ai.ui.dashboard

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.chip.Chip
import com.raksha.ai.R
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class SecurityEventAdapter : RecyclerView.Adapter<SecurityEventAdapter.EventViewHolder>() {

    private val events = mutableListOf<SecurityEvent>()

    fun submitList(newEvents: List<SecurityEvent>) {
        events.clear()
        events.addAll(newEvents)
        notifyDataSetChanged()
    }

    fun addEvent(event: SecurityEvent) {
        events.add(0, event)
        notifyItemInserted(0)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EventViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_security_event, parent, false)
        return EventViewHolder(view)
    }

    override fun onBindViewHolder(holder: EventViewHolder, position: Int) {
        holder.bind(events[position])
    }

    override fun getItemCount(): Int = events.size

    class EventViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val senderView: TextView = itemView.findViewById<TextView>(R.id.senderText)
        private val messageView: TextView = itemView.findViewById<TextView>(R.id.messageText)
        private val timestampView: TextView = itemView.findViewById<TextView>(R.id.timestampText)
        private val urlChip: Chip = itemView.findViewById<Chip>(R.id.urlChip)
        private val attachmentChip: Chip = itemView.findViewById<Chip>(R.id.attachmentChip)

        fun bind(event: SecurityEvent) {
            senderView.text = event.sender ?: itemView.context.getString(R.string.unknown_sender)
            messageView.text = event.message_text.ifBlank {
                itemView.context.getString(R.string.no_message_text)
            }
            timestampView.text = formatTimestamp(event.timestamp)
            configureIndicator(urlChip, event.urls.isNotEmpty())
            configureIndicator(attachmentChip, event.attachments.isNotEmpty())
            urlChip.text = event.urls.size.toString()
            attachmentChip.text = event.attachments.size.toString()
        }

        private fun configureIndicator(chip: Chip, isActive: Boolean) {
            if (isActive) {
                chip.chipBackgroundColor =
                    itemView.context.getColorStateList(R.color.risk_chip_background)
                chip.setTextColor(itemView.context.getColor(R.color.risk_chip_text))
                chip.chipIconTint = itemView.context.getColorStateList(R.color.risk_chip_text)
            } else {
                chip.chipBackgroundColor =
                    itemView.context.getColorStateList(R.color.chip_background)
                chip.setTextColor(itemView.context.getColor(R.color.chip_text))
                chip.chipIconTint = itemView.context.getColorStateList(R.color.chip_text)
            }
        }

        private fun formatTimestamp(isoTimestamp: String): String {
            return try {
                val instant = Instant.parse(isoTimestamp)
                DISPLAY_FORMATTER.format(instant.atZone(ZoneId.systemDefault()))
            } catch (_: Exception) {
                isoTimestamp
            }
        }

        companion object {
            private val DISPLAY_FORMATTER = DateTimeFormatter.ofPattern("MMM d, h:mm a")
        }
    }
}
