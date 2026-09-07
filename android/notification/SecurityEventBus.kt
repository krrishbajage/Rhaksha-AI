package com.raksha.ai.notification

import com.raksha.ai.models.SecurityEvent
import java.util.concurrent.CopyOnWriteArrayList

object SecurityEventBus {

    private val events = CopyOnWriteArrayList<SecurityEvent>()
    private val listeners = CopyOnWriteArrayList<(SecurityEvent) -> Unit>()

    fun getEvents(): List<SecurityEvent> = events.toList()

    fun addListener(listener: (SecurityEvent) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (SecurityEvent) -> Unit) {
        listeners.remove(listener)
    }

    fun upsert(event: SecurityEvent) {
        val index = events.indexOfFirst { it.event_id == event.event_id }
        if (index >= 0) {
            events[index] = event
        } else {
            events.add(0, event)
        }
        listeners.forEach { it(event) }
    }
}
