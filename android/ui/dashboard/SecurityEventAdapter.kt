package com.raksha.ai.ui.dashboard

import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.raksha.ai.R
import com.raksha.ai.models.AnalysisStatus
import com.raksha.ai.models.SecurityEvent
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class SecurityEventAdapter(
    private val onEventClick: (SecurityEvent) -> Unit = {}
) : RecyclerView.Adapter<SecurityEventAdapter.EventViewHolder>() {

    private val events = mutableListOf<SecurityEvent>()
    private val expandedIds = mutableSetOf<String>()

    fun submitList(newEvents: List<SecurityEvent>) {
        events.clear()
        events.addAll(newEvents)
        notifyDataSetChanged()
    }

    fun upsertEvent(event: SecurityEvent): Boolean {
        val index = events.indexOfFirst { it.event_id == event.event_id }
        return if (index >= 0) {
            events[index] = event
            notifyItemChanged(index)
            false
        } else {
            events.add(0, event)
            notifyItemInserted(0)
            true
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): EventViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_security_event, parent, false)
        return EventViewHolder(view)
    }

    override fun onBindViewHolder(holder: EventViewHolder, position: Int) {
        val event = events[position]
        holder.bind(event, expandedIds.contains(event.event_id), { onEventClick(event) }) {
            if (!expandedIds.add(event.event_id)) {
                expandedIds.remove(event.event_id)
            }
            notifyItemChanged(holder.bindingAdapterPosition)
        }
    }

    override fun getItemCount(): Int = events.size

    class EventViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val senderView: TextView = itemView.findViewById(R.id.senderText)
        private val messageView: TextView = itemView.findViewById(R.id.messageText)
        private val timestampView: TextView = itemView.findViewById(R.id.timestampText)
        private val pendingRow: LinearLayout = itemView.findViewById(R.id.pendingRow)
        private val resultRow: LinearLayout = itemView.findViewById(R.id.resultRow)
        private val riskBadge: TextView = itemView.findViewById(R.id.riskBadge)
        private val categoryText: TextView = itemView.findViewById(R.id.categoryText)
        private val detailsContainer: LinearLayout = itemView.findViewById(R.id.detailsContainer)
        private val explanationText: TextView = itemView.findViewById(R.id.explanationText)
        private val actionText: TextView = itemView.findViewById(R.id.actionText)

        fun bind(event: SecurityEvent, expanded: Boolean, onOpen: () -> Unit, onToggle: () -> Unit) {
            senderView.text = event.sender ?: itemView.context.getString(R.string.unknown_sender)
            messageView.text = event.message_text.ifBlank {
                itemView.context.getString(R.string.no_message_text)
            }
            timestampView.text = formatTimestamp(event.timestamp)
            itemView.contentDescription = itemView.context.getString(
                R.string.event_content_description,
                senderView.text,
                event.displayRisk,
                messageView.text
            )

            when (event.analysisStatus) {
                AnalysisStatus.PENDING -> {
                    pendingRow.visibility = View.VISIBLE
                    resultRow.visibility = View.GONE
                    detailsContainer.visibility = View.GONE
                    itemView.isClickable = true
                    itemView.setOnClickListener { onOpen() }
                    itemView.setOnLongClickListener(null)
                }
                AnalysisStatus.FAILED -> {
                    pendingRow.visibility = View.GONE
                    resultRow.visibility = View.VISIBLE
                    bindBadge(
                        itemView.context.getString(R.string.risk_failed),
                        R.color.risk_failed,
                        R.color.on_risk_badge
                    )
                    categoryText.text = itemView.context.getString(R.string.risk_failed)
                    detailsContainer.visibility = if (expanded) View.VISIBLE else View.GONE
                    explanationText.text = itemView.context.getString(R.string.risk_failed)
                    actionText.text = event.failureReason ?: itemView.context.getString(R.string.risk_failed)
                    itemView.isClickable = true
                    itemView.setOnClickListener { onOpen() }
                    itemView.setOnLongClickListener {
                        onToggle()
                        true
                    }
                }
                AnalysisStatus.COMPLETE -> {
                    pendingRow.visibility = View.GONE
                    resultRow.visibility = View.VISIBLE
                    val report = event.riskReport
                    val level = report?.risk_level ?: itemView.context.getString(R.string.risk_unknown)
                    bindBadge(level, badgeColor(level), badgeTextColor(level))
                    val category = report?.scam_category.orEmpty()
                    categoryText.text = if (category.isBlank() || category == "none") {
                        itemView.context.getString(R.string.category_none)
                    } else {
                        category.replace('_', ' ')
                    }
                    explanationText.text = report?.explanation.orEmpty()
                    actionText.text = report?.recommended_action.orEmpty()
                    detailsContainer.visibility = if (expanded) View.VISIBLE else View.GONE
                    itemView.isClickable = true
                    itemView.setOnClickListener { onOpen() }
                    itemView.setOnLongClickListener {
                        onToggle()
                        true
                    }
                }
            }
        }

        private fun bindBadge(label: String, backgroundColor: Int, textColor: Int) {
            riskBadge.text = label
            val drawable = GradientDrawable().apply {
                cornerRadius = itemView.resources.displayMetrics.density * 8
                setColor(ContextCompat.getColor(itemView.context, backgroundColor))
            }
            riskBadge.background = drawable
            riskBadge.setTextColor(ContextCompat.getColor(itemView.context, textColor))
        }

        private fun badgeColor(level: String): Int {
            return when (level.lowercase()) {
                "low", "safe" -> R.color.risk_low
                "medium" -> R.color.risk_medium
                "high", "critical" -> R.color.risk_high
                else -> R.color.risk_pending
            }
        }

        private fun badgeTextColor(level: String): Int {
            return if (level.lowercase() == "medium") {
                R.color.on_risk_medium
            } else {
                R.color.on_risk_badge
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
