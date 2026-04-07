package com.example.appletvremote.discovery

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import com.example.appletvremote.model.AppleTVDevice
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.InetAddress
import javax.jmdns.JmDNS
import javax.jmdns.ServiceEvent
import javax.jmdns.ServiceListener

/**
 * Discovers Apple TV devices using JmDNS (pure Java mDNS).
 * Android's built-in NsdManager is unreliable on many devices,
 * so we use JmDNS directly with a multicast lock.
 */
class AppleTVDiscovery(private val context: Context) {
    companion object {
        private const val TAG = "AppleTVDiscovery"
        // Apple TV advertises on both of these
        private val SERVICE_TYPES = arrayOf(
            "_mediaremotetv._tcp.local.",
            "_airplay._tcp.local."
        )
    }

    private var multicastLock: WifiManager.MulticastLock? = null
    private var jmdns: JmDNS? = null
    private var discoveryJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _devices = MutableStateFlow<List<AppleTVDevice>>(emptyList())
    val devices: StateFlow<List<AppleTVDevice>> = _devices
    private val deviceMap = mutableMapOf<String, AppleTVDevice>()

    fun startDiscovery() {
        // Stop any existing discovery first
        stopDiscovery()

        deviceMap.clear()
        _devices.value = emptyList()

        discoveryJob = scope.launch {
            try {
                // Acquire multicast lock
                val wifiManager = context.applicationContext
                    .getSystemService(Context.WIFI_SERVICE) as WifiManager
                multicastLock = wifiManager.createMulticastLock("atvremote_jmdns").apply {
                    setReferenceCounted(false)
                    acquire()
                }
                Log.d(TAG, "Multicast lock acquired")

                // Get the device's WiFi IP address to bind JmDNS to the right interface
                val wifiInfo = wifiManager.connectionInfo
                val ipInt = wifiInfo.ipAddress
                val ipBytes = byteArrayOf(
                    (ipInt and 0xFF).toByte(),
                    ((ipInt shr 8) and 0xFF).toByte(),
                    ((ipInt shr 16) and 0xFF).toByte(),
                    ((ipInt shr 24) and 0xFF).toByte()
                )
                val inetAddr = InetAddress.getByAddress(ipBytes)
                Log.d(TAG, "Binding JmDNS to ${inetAddr.hostAddress}")

                // Create JmDNS instance bound to WiFi interface
                val mdns = JmDNS.create(inetAddr, "AndroidATVRemote")
                jmdns = mdns
                Log.d(TAG, "JmDNS created")

                val listener = object : ServiceListener {
                    override fun serviceAdded(event: ServiceEvent) {
                        Log.d(TAG, "Service added: ${event.name} (${event.type})")
                        // Request full info
                        mdns.requestServiceInfo(event.type, event.name, true, 3000)
                    }

                    override fun serviceRemoved(event: ServiceEvent) {
                        Log.d(TAG, "Service removed: ${event.name}")
                        synchronized(deviceMap) {
                            deviceMap.entries.removeIf {
                                it.value.name == event.name
                            }
                            _devices.value = deviceMap.values.toList()
                        }
                    }

                    override fun serviceResolved(event: ServiceEvent) {
                        val info = event.info
                        val addresses = info.inet4Addresses
                        if (addresses.isEmpty()) {
                            Log.d(TAG, "Resolved ${event.name} but no IPv4 address")
                            return
                        }

                        val host = addresses[0].hostAddress ?: return
                        val port = info.port
                        val name = info.name

                        // Only use _mediaremotetv port; skip _airplay unless
                        // it's the only way we found this device
                        val isMRP = event.type.contains("mediaremotetv")
                        val uniqueId = info.getPropertyString("UniqueIdentifier")
                            ?: info.getPropertyString("deviceid")
                            ?: info.getPropertyString("MACAddress")
                            ?: "$host:$port"

                        Log.d(TAG, "Resolved: $name at $host:$port type=${event.type} id=$uniqueId")

                        val device = AppleTVDevice(
                            name = name,
                            host = host,
                            port = if (isMRP) port else 49152,
                            uniqueId = uniqueId
                        )

                        synchronized(deviceMap) {
                            // Prefer MRP entry over airplay entry for same device
                            val existing = deviceMap[uniqueId]
                            if (existing == null || isMRP) {
                                deviceMap[uniqueId] = device
                                _devices.value = deviceMap.values.toList()
                            }
                        }
                    }
                }

                // Register listeners for all service types
                for (serviceType in SERVICE_TYPES) {
                    Log.d(TAG, "Adding listener for $serviceType")
                    mdns.addServiceListener(serviceType, listener)
                }

                // Also do an explicit list query for each type
                // (some devices only respond to queries, not continuous listening)
                for (serviceType in SERVICE_TYPES) {
                    launch {
                        try {
                            Log.d(TAG, "Listing services for $serviceType")
                            val services = mdns.list(serviceType, 6000)
                            Log.d(TAG, "Found ${services.size} services for $serviceType")
                            for (info in services) {
                                val addresses = info.inet4Addresses
                                if (addresses.isEmpty()) continue
                                val host = addresses[0].hostAddress ?: continue
                                val port = info.port
                                val name = info.name
                                val isMRP = serviceType.contains("mediaremotetv")
                                val uniqueId = info.getPropertyString("UniqueIdentifier")
                                    ?: info.getPropertyString("deviceid")
                                    ?: info.getPropertyString("MACAddress")
                                    ?: "$host:$port"

                                val device = AppleTVDevice(
                                    name = name,
                                    host = host,
                                    port = if (isMRP) port else 49152,
                                    uniqueId = uniqueId
                                )
                                synchronized(deviceMap) {
                                    val existing = deviceMap[uniqueId]
                                    if (existing == null || isMRP) {
                                        deviceMap[uniqueId] = device
                                        _devices.value = deviceMap.values.toList()
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error listing $serviceType: ${e.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Discovery failed: ${e.message}", e)
            }
        }
    }

    fun stopDiscovery() {
        discoveryJob?.cancel()
        discoveryJob = null
        try {
            jmdns?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing JmDNS: ${e.message}")
        }
        jmdns = null
        try {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
            }
        } catch (_: Exception) {}
        multicastLock = null
    }
}
