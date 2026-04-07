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

    fun selectDevice(device: AppleTVDevice) {
        Log.d(TAG, "selectDevice: ${device.name} at ${device.host}:${device.port}")
        _selectedDevice.value = device
        // Don't wait for discovery to stop — it's async now
        discovery.stopDiscovery()
        connectToDevice(device)
    }

    fun connectManual(ip: String) {
        val host = ip.trim()
        if (host.isEmpty()) return
        discovery.stopDiscovery()
        val device = AppleTVDevice(
            name = "Apple TV ($host)",
            host = host,
            port = 49152, // Default MRP port
            uniqueId = host
        )
        _selectedDevice.value = device
        connectToDevice(device)
    }

    private fun connectToDevice(device: AppleTVDevice) {
        viewModelScope.launch {
            try {
                _connectionState.value = ConnectionState.CONNECTING
                _statusMessage.value = "Connecting to ${device.name}..."

                val conn = MrpConnection()
                conn.connect(device.host, device.port)
                connection = conn

                // Check if we have stored credentials for this device
                val creds = credentialStore.load(device.uniqueId)
                if (creds != null) {
                    // Try pair-verify with existing credentials
                    _connectionState.value = ConnectionState.PAIR_VERIFY
                    _statusMessage.value = "Verifying pairing..."
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
                        // Reconnect since the failed pair-verify may have disrupted the connection
                        conn.disconnect()
                        val newConn = MrpConnection()
                        newConn.connect(device.host, device.port)
                        connection = newConn
                    }
                }

                // Need to do initial pairing
                startPairing()
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}", e)
                _statusMessage.value = "Connection failed: ${e.message}"
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    private suspend fun startPairing() {
        val conn = connection ?: return
        try {
            _connectionState.value = ConnectionState.PAIRING
            _statusMessage.value = "Starting pairing... Check your Apple TV for a PIN."

            val mrpPairing = MrpPairing(conn)
            pairing = mrpPairing

            // M1: Start pairing
            mrpPairing.pairSetupM1()

            // M2: Get challenge (Apple TV shows PIN on screen)
            val (salt, serverPubKey) = mrpPairing.pairSetupM2()
            pairingSalt = salt
            pairingServerPubKey = serverPubKey

            _needsPin.value = true
            _statusMessage.value = "Enter the PIN shown on your Apple TV"
        } catch (e: Exception) {
            Log.e(TAG, "Pairing start failed: ${e.message}", e)
            _statusMessage.value = "Pairing failed: ${e.message}"
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

                // M3: Send proof with PIN
                mrpPairing.pairSetupM3(pin, salt, serverPubKey)

                // M4: Verify server proof
                mrpPairing.pairSetupM4()

                // M5: Send encrypted credentials
                mrpPairing.pairSetupM5()

                // M6: Receive server credentials
                val device = _selectedDevice.value!!
                var creds = mrpPairing.pairSetupM6()
                creds = creds.copy(deviceId = device.uniqueId)

                // Save credentials
                credentialStore.save(creds)

                _statusMessage.value = "Pairing successful! Establishing encrypted connection..."

                // Now do pair-verify to establish encrypted session
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
                _statusMessage.value = "Pairing failed: ${e.message}"
                _connectionState.value = ConnectionState.DISCONNECTED
            }
        }
    }

    fun pressButton(button: RemoteButton) {
        val conn = connection ?: return
        if (_connectionState.value != ConnectionState.CONNECTED) return

        viewModelScope.launch {
            try {
                // Send button down
                val downMsg = ProtobufHelper.buildSendHIDEventMessage(
                    button.usagePage, button.usage, true
                )
                conn.sendMessage(downMsg)

                // Small delay between down and up
                delay(50)

                // Send button up
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
