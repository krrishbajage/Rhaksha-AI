package com.raksha.ai.network

/**
 * Edit [LAPTOP_LOCAL_IP] only. Everything else is derived from it.
 *
 * Windows: run `ipconfig` and copy the IPv4 Address for your Wi-Fi adapter
 * (example: 192.168.1.12). Phone and laptop must be on the same Wi-Fi.
 * Emulator: use 10.0.2.2 instead of a LAN IP.
 */
object NetworkConfig {
    const val LAPTOP_LOCAL_IP = "10.25.28.238"
    const val BACKEND_PORT = 8000
    const val BASE_URL = "http://$LAPTOP_LOCAL_IP:$BACKEND_PORT/"
}