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

class RemoteViewModel(application: Application) : AndroidViewModel(application) {
    companion object {
        private const val TAG = "RemoteViewModel"
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

    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    private var connection: MrpConnection? = null
    private var pairing: MrpPairing? = null
    private var pairingSalt: ByteArray? = null
    private var pairingServerPubKey: ByteArray? = null

    fun startDiscovery() {
        _connectionState.value = ConnectionState.DISCOVERING
        _statusMessage.value = "Searching for Apple TV..."
        discovery.startDiscovery()
    }

    fun stopDiscovery() {
        discovery.stopDiscovery()
        if (_connectionState.value == ConnectionState.DISCOVERING) {
            _connectionState.value = ConnectionState.DISCONNECTED
        }
    }

    fun clearError() {
        _lastError.value = ""
    }

    fun selectDevice(device: AppleTVDevice) {
        Log.d(TAG, "selectDevice: ${device.name} at ${device.host}:${device.port}")
        _selectedDevice.value = device
        _lastError.value = ""
        discovery.stopDiscovery()
        _connectionState.value = ConnectionState.CONNECTING
        _statusMessage.value = "Connecting to ${device.name} (${device.host}:${device.port})..."
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
        _statusMessage.value = "Connecting to $host:49152..."
        connectToDevice(device)
    }

    private fun connectToDevice(device: AppleTVDevice) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Connecting to ${device.host}:${device.port}")
                val conn = MrpConnection()
                conn.connect(device.host, device.port)
                connection = conn
                val transport = if (conn.usingTls) "TLS" else "TCP"
                Log.d(TAG, "Connected via $transport to ${device.host}:${device.port}")

                // Send DeviceInfo first (always required)
                _statusMessage.value = "Connected via $transport, identifying..."
                val mrpPairingInit = MrpPairing(conn)
                mrpPairingInit.sendDeviceInfo()
                Log.d(TAG, "DeviceInfo exchange complete")

                // Check if we have stored credentials for this device
                val creds = credentialStore.load(device.uniqueId)
                if (creds != null) {
                    _connectionState.value = ConnectionState.PAIR_VERIFY
                    _statusMessage.value = "Verifying existing pairing..."
                    try {
                        val cipher = mrpPairingInit.pairVerify(creds)
                        conn.cipher = cipher
                        _connectionState.value = ConnectionState.CONNECTED
                        _statusMessage.value = "Connected to ${device.name}"
                        return@launch
                    } catch (e: Exception) {
                        Log.w(TAG, "Pair-verify failed: ${e.message}")
                        credentialStore.delete(device.uniqueId)
                        conn.disconnect()
                        val newConn = MrpConnection()
                        newConn.connect(device.host, device.port)
                        connection = newConn
                        // Send DeviceInfo on new connection
                        val newPairing = MrpPairing(newConn)
                        newPairing.sendDeviceInfo()
                        startPairing(newPairing)
                        return@launch
                    }
                }

                startPairing(mrpPairingInit)
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}", e)
                _lastError.value = "Failed to connect to ${device.host}:${device.port} — ${e.javaClass.simpleName}: ${e.message}"
                _statusMessage.value = ""
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    private suspend fun startPairing(mrpPairing: MrpPairing) {
        val device = _selectedDevice.value ?: return
        try {
            _connectionState.value = ConnectionState.PAIRING
            _statusMessage.value = "Sending pairing request to ${device.host}:${device.port}..."
            Log.d(TAG, "Starting pair-setup M1")

            pairing = mrpPairing

            mrpPairing.pairSetupM1()
            _statusMessage.value = "Pairing M1 sent, waiting for Apple TV response..."
            Log.d(TAG, "M1 sent, waiting for M2")

            val (salt, serverPubKey) = mrpPairing.pairSetupM2()
            Log.d(TAG, "M2 received: salt=${salt.size}B pubkey=${serverPubKey.size}B")
            pairingSalt = salt
            pairingServerPubKey = serverPubKey

            _needsPin.value = true
            _statusMessage.value = "Enter the PIN shown on your Apple TV"
        } catch (e: Exception) {
            Log.e(TAG, "Pairing failed at ${_statusMessage.value}: ${e.message}", e)
            _lastError.value = "Pairing failed at step [${_statusMessage.value}]\n\n" +
                    "Port: ${device.host}:${device.port}\n" +
                    "Error: ${e.javaClass.simpleName}: ${e.message}"
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

                _statusMessage.value = "Checking server proof (M4)..."
                mrpPairing.pairSetupM4()

                _statusMessage.value = "Sending credentials (M5)..."
                mrpPairing.pairSetupM5()

                _statusMessage.value = "Receiving server credentials (M6)..."
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
                _lastError.value = "Pairing failed: ${e.javaClass.simpleName}: ${e.message}"
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
                Log.e(TAG, "Failed to send button: ${e.message}", e)
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
