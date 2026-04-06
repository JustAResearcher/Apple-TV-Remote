package com.example.appletvremote.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import com.example.appletvremote.model.AppleTVDevice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Discovers Apple TV devices on the local network using mDNS/NSD.
 * Looks for _mediaremotetv._tcp services (MRP protocol).
 *
 * Requires a WiFi multicast lock — Android suppresses multicast by default
 * to save battery, which prevents mDNS from receiving responses.
 */
class AppleTVDiscovery(private val context: Context) {
    companion object {
        private const val TAG = "AppleTVDiscovery"
        private const val SERVICE_TYPE = "_mediaremotetv._tcp."
    }

    private var nsdManager: NsdManager? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private val _devices = MutableStateFlow<List<AppleTVDevice>>(emptyList())
    val devices: StateFlow<List<AppleTVDevice>> = _devices
    private val deviceMap = mutableMapOf<String, AppleTVDevice>()
    private var isDiscovering = false
    private var listener: NsdManager.DiscoveryListener? = null

    private fun getNsdManager(): NsdManager? {
        if (nsdManager == null) {
            nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
        }
        return nsdManager
    }

    private fun acquireMulticastLock() {
        if (multicastLock?.isHeld == true) return
        try {
            val wifiManager = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as? WifiManager
            multicastLock = wifiManager?.createMulticastLock("atvremote_mdns")?.apply {
                setReferenceCounted(false)
                acquire()
            }
            Log.d(TAG, "Multicast lock acquired")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire multicast lock: ${e.message}")
        }
    }

    private fun releaseMulticastLock() {
        try {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
                Log.d(TAG, "Multicast lock released")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to release multicast lock: ${e.message}")
        }
        multicastLock = null
    }

    fun startDiscovery() {
        if (isDiscovering) return

        val mgr = getNsdManager()
        if (mgr == null) {
            Log.e(TAG, "NsdManager not available")
            return
        }

        // Must acquire multicast lock BEFORE starting discovery
        acquireMulticastLock()

        deviceMap.clear()
        _devices.value = emptyList()

        listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                Log.d(TAG, "Discovery started for $regType")
                isDiscovering = true
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service found: ${serviceInfo.serviceName}")
                try {
                    mgr.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(si: NsdServiceInfo, errorCode: Int) {
                            Log.e(TAG, "Resolve failed for ${si.serviceName}: error $errorCode")
                        }

                        override fun onServiceResolved(si: NsdServiceInfo) {
                            try {
                                val host = si.host?.hostAddress ?: return
                                val port = si.port
                                val name = si.serviceName
                                val uniqueId = try {
                                    si.attributes["UniqueIdentifier"]?.let { String(it) }
                                        ?: si.attributes["MACAddress"]?.let { String(it) }
                                        ?: "$host:$port"
                                } catch (_: Exception) {
                                    "$host:$port"
                                }

                                Log.d(TAG, "Resolved: $name at $host:$port (id=$uniqueId)")
                                val device = AppleTVDevice(name, host, port, uniqueId)
                                synchronized(deviceMap) {
                                    deviceMap[uniqueId] = device
                                    _devices.value = deviceMap.values.toList()
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Error processing resolved service: ${e.message}")
                            }
                        }
                    })
                } catch (e: Exception) {
                    Log.e(TAG, "Error resolving service: ${e.message}")
                }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service lost: ${serviceInfo.serviceName}")
                synchronized(deviceMap) {
                    deviceMap.entries.removeIf { it.value.name == serviceInfo.serviceName }
                    _devices.value = deviceMap.values.toList()
                }
            }

            override fun onDiscoveryStopped(serviceType: String) {
                Log.d(TAG, "Discovery stopped")
                isDiscovering = false
            }

            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Start discovery failed: error $errorCode")
                isDiscovering = false
            }

            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.e(TAG, "Stop discovery failed: error $errorCode")
            }
        }

        try {
            mgr.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start discovery: ${e.message}")
            releaseMulticastLock()
        }
    }

    fun stopDiscovery() {
        if (!isDiscovering) return
        try {
            val mgr = nsdManager ?: return
            listener?.let { mgr.stopServiceDiscovery(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop discovery: ${e.message}")
        }
        isDiscovering = false
        releaseMulticastLock()
    }
}
