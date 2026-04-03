package com.example.appletvremote.discovery

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.util.Log
import com.example.appletvremote.model.AppleTVDevice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Discovers Apple TV devices on the local network using mDNS/NSD.
 * Looks for _mediaremotetv._tcp services (MRP protocol).
 */
class AppleTVDiscovery(context: Context) {
    companion object {
        private const val TAG = "AppleTVDiscovery"
        private const val SERVICE_TYPE = "_mediaremotetv._tcp."
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val _devices = MutableStateFlow<List<AppleTVDevice>>(emptyList())
    val devices: StateFlow<List<AppleTVDevice>> = _devices
    private val deviceMap = mutableMapOf<String, AppleTVDevice>()
    private var isDiscovering = false
    private var listener: NsdManager.DiscoveryListener? = null

    fun startDiscovery() {
        if (isDiscovering) return
        deviceMap.clear()
        _devices.value = emptyList()

        listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                Log.d(TAG, "Discovery started for $regType")
                isDiscovering = true
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                Log.d(TAG, "Service found: ${serviceInfo.serviceName}")
                nsdManager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(si: NsdServiceInfo, errorCode: Int) {
                        Log.e(TAG, "Resolve failed for ${si.serviceName}: error $errorCode")
                    }

                    override fun onServiceResolved(si: NsdServiceInfo) {
                        val host = si.host?.hostAddress ?: return
                        val port = si.port
                        val name = si.serviceName
                        val uniqueId = si.attributes["UniqueIdentifier"]?.let { String(it) }
                            ?: si.attributes["MACAddress"]?.let { String(it) }
                            ?: "$host:$port"

                        Log.d(TAG, "Resolved: $name at $host:$port (id=$uniqueId)")
                        val device = AppleTVDevice(name, host, port, uniqueId)
                        synchronized(deviceMap) {
                            deviceMap[uniqueId] = device
                            _devices.value = deviceMap.values.toList()
                        }
                    }
                })
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
            nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start discovery: ${e.message}")
        }
    }

    fun stopDiscovery() {
        if (!isDiscovering) return
        try {
            listener?.let { nsdManager.stopServiceDiscovery(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop discovery: ${e.message}")
        }
        isDiscovering = false
    }
}
