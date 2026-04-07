package com.example.appletvremote.viewmodel

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.appletvremote.discovery.AppleTVDiscovery
import com.example.appletvremote.model.*
import com.example.appletvremote.protocol.MrpConnection
import com.example.appletvremote.protocol.MrpPairing
import com.example.appletvremote.protocol.ProtobufHelper
import com.example.appletvremote.storage.CredentialStore
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.InetSocketAddress
import java.net.Socket

class RemoteViewModel(application: Application) : AndroidViewModel(application) {
    companion object {
        private const val TAG = "RemoteViewModel"
        // Apple TV MRP commonly listens on these ports
        private val MRP_PORTS = listOf(49152, 49153, 49154, 49155, 49156, 32498)
    }

    val discovery = AppleTVDiscovery(application)
    private val credentialStore = CredentialStore(application)

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState

    private val _statusMessage = MutableStateFlow("")
    val statusMessage: StateFlow<String> = _statusMessage

    private val _selectedDevice = MutableStateFlow<AppleTVDevice?>(null)
    val selectedDevice: StateFlow<AppleTVDevice?> = _selectedDevice

    private val _needsPin = MutableStateFlow(false)
    val needsPin: StateFlow<Boolean> = _needsPin

    // Error that persists on the discovery screen
    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    private var connection: MrpConnection? = null
    private var pairing: MrpPairing? = null
    private var pairingSalt: ByteArray? = null
    private var pairingServerPubKey: ByteArray? = null

    fun startDiscovery() {
        _connectionState.value = ConnectionState.DISCOVERING
        _statusMessage.value = "Searching for Apple TV..."
        _lastError.value = ""
        discovery.startDiscovery()
    }

    fun stopDiscovery() {
        discovery.stopDiscovery()
        if (_connectionState.value == ConnectionState.DISCOVERING) {
            _connectionState.value = ConnectionState.DISCONNECTED
        }
    }

    fun selectDevice(device: AppleTVDevice) {
        Log.d(TAG, "selectDevice: ${device.name} at ${device.host}:${device.port}")
        _selectedDevice.value = device
        _lastError.value = ""
        discovery.stopDiscovery()
        // Change state BEFORE launching coroutine for immediate UI feedback
        _connectionState.value = ConnectionState.CONNECTING
        _statusMessage.value = "Connecting to ${device.name}..."
        connectToDevice(device)
    }

    fun connectManual(ip: String) {
        val host = ip.trim()
        if (host.isEmpty()) return
        discovery.stopDiscovery()
        val device = AppleTVDevice(
            name = "Apple TV ($host)",
            host = host,
            port = 49152,
            uniqueId = host
        )
        _selectedDevice.value = device
        _lastError.value = ""
        _connectionState.value = ConnectionState.CONNECTING
        _statusMessage.value = "Connecting to $host..."
        connectToDevice(device)
    }

    private fun connectToDevice(device: AppleTVDevice) {
        viewModelScope.launch {
            try {
                // Try the discovered port first, then scan common MRP ports
                val port = findWorkingPort(device.host, device.port)
                if (port == null) {
                    Log.e(TAG, "No open MRP port found on ${device.host}")
                    _lastError.value = "Could not connect to ${device.name} — no open port found on ${device.host}. Tried ports: ${device.port}, ${MRP_PORTS.joinToString()}"
                    _statusMessage.value = ""
                    _connectionState.value = ConnectionState.DISCONNECTED
                    return@launch
                }

                _statusMessage.value = "Connected on port $port, starting pairing..."
                Log.d(TAG, "Found open port $port on ${device.host}")

                val conn = MrpConnection()
                conn.connect(device.host, port)
                connection = conn

                // Check if we have stored credentials for this device
                val creds = credentialStore.load(device.uniqueId)
                if (creds != null) {
                    _connectionState.value = ConnectionState.PAIR_VERIFY
                    _statusMessage.value = "Verifying existing pairing..."
                    try {
                        val mrpPairing = MrpPairing(conn)
                        val cipher = mrpPairing.pairVerify(creds)
                        conn.cipher = cipher
                        _connectionState.value = ConnectionState.CONNECTED
                        _statusMessage.value = "Connected to ${device.name}"
                        return@launch
                    } catch (e: Exception) {
                        Log.w(TAG, "Pair-verify failed, need to re-pair: ${e.message}")
                        credentialStore.delete(device.uniqueId)
                        conn.disconnect()
                        val newConn = MrpConnection()
                        newConn.connect(device.host, port)
                        connection = newConn
                    }
                }

                // Need to do initial pairing
                startPairing()
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}", e)
                _lastError.value = "Connection failed: ${e.message}"
                _statusMessage.value = ""
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    /**
     * Try to find an open MRP port on the Apple TV.
     * First tries the port from mDNS, then scans common MRP ports.
     */
    private suspend fun findWorkingPort(host: String, discoveredPort: Int): Int? = withContext(Dispatchers.IO) {
        // Build list: discovered port first, then fallbacks (deduplicated)
        val portsToTry = (listOf(discoveredPort) + MRP_PORTS).distinct()

        for (port in portsToTry) {
            try {
                _statusMessage.value = "Trying $host:$port..."
                Log.d(TAG, "Trying port $port on $host")
                val sock = Socket()
                sock.connect(InetSocketAddress(host, port), 2000)
                sock.close()
                Log.d(TAG, "Port $port is open on $host")
                return@withContext port
            } catch (e: Exception) {
                Log.d(TAG, "Port $port closed/timeout on $host: ${e.message}")
            }
        }
        null
    }

    private suspend fun startPairing() {
        val conn = connection ?: return
        try {
            _connectionState.value = ConnectionState.PAIRING
            _statusMessage.value = "Starting pairing... Check your Apple TV for a PIN."

            val mrpPairing = MrpPairing(conn)
            pairing = mrpPairing

            mrpPairing.pairSetupM1()

            val (salt, serverPubKey) = mrpPairing.pairSetupM2()
            pairingSalt = salt
            pairingServerPubKey = serverPubKey

            _needsPin.value = true
            _statusMessage.value = "Enter the PIN shown on your Apple TV"
        } catch (e: Exception) {
            Log.e(TAG, "Pairing start failed: ${e.message}", e)
            _lastError.value = "Pairing failed: ${e.message}"
            _statusMessage.value = ""
            _connectionState.value = ConnectionState.DISCONNECTED
        }
    }

    fun submitPin(pin: String) {
        _needsPin.value = false
        viewModelScope.launch {
            try {
                val mrpPairing = pairing ?: throw IllegalStateException("No active pairing")
                val salt = pairingSalt ?: throw IllegalStateException("No salt")
                val serverPubKey = pairingServerPubKey ?: throw IllegalStateException("No server key")

                _statusMessage.value = "Verifying PIN..."

                mrpPairing.pairSetupM3(pin, salt, serverPubKey)
                mrpPairing.pairSetupM4()
                mrpPairing.pairSetupM5()

                val device = _selectedDevice.value!!
                var creds = mrpPairing.pairSetupM6()
                creds = creds.copy(deviceId = device.uniqueId)

                credentialStore.save(creds)

                _statusMessage.value = "Pairing successful! Establishing encrypted connection..."

                connection?.disconnect()
                val newConn = MrpConnection()
                newConn.connect(device.host, device.port)
                connection = newConn

                val verifyPairing = MrpPairing(newConn)
                val cipher = verifyPairing.pairVerify(creds)
                newConn.cipher = cipher

                _connectionState.value = ConnectionState.CONNECTED
                _statusMessage.value = "Connected to ${device.name}"
            } catch (e: Exception) {
                Log.e(TAG, "Pairing failed: ${e.message}", e)
                _lastError.value = "Pairing failed: ${e.message}"
                _statusMessage.value = ""
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    fun pressButton(button: RemoteButton) {
        val conn = connection ?: return
        if (_connectionState.value != ConnectionState.CONNECTED) return

        viewModelScope.launch {
            try {
                val downMsg = ProtobufHelper.buildSendHIDEventMessage(
                    button.usagePage, button.usage, true
                )
                conn.sendMessage(downMsg)
                delay(50)
                val upMsg = ProtobufHelper.buildSendHIDEventMessage(
                    button.usagePage, button.usage, false
                )
                conn.sendMessage(upMsg)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send button press: ${e.message}", e)
                _statusMessage.value = "Command failed: ${e.message}"
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    fun disconnect() {
        connection?.disconnect()
        connection = null
        pairing = null
        _connectionState.value = ConnectionState.DISCONNECTED
        _selectedDevice.value = null
        _statusMessage.value = ""
        _needsPin.value = false
    }

    override fun onCleared() {
        super.onCleared()
        discovery.stopDiscovery()
        connection?.disconnect()
    }
}
