package com.example.appletvremote

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.appletvremote.model.ConnectionState
import com.example.appletvremote.ui.screens.DiscoveryScreen
import com.example.appletvremote.ui.screens.PairingScreen
import com.example.appletvremote.ui.screens.RemoteScreen
import com.example.appletvremote.viewmodel.RemoteViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    RemoteApp()
                }
            }
        }
    }
}

@Composable
fun RemoteApp(viewModel: RemoteViewModel = viewModel()) {
    val connectionState by viewModel.connectionState.collectAsState()
    val statusMessage by viewModel.statusMessage.collectAsState()
    val devices by viewModel.discovery.devices.collectAsState()
    val selectedDevice by viewModel.selectedDevice.collectAsState()
    val needsPin by viewModel.needsPin.collectAsState()

    when (connectionState) {
        ConnectionState.DISCONNECTED,
        ConnectionState.DISCOVERING -> {
            DiscoveryScreen(
                devices = devices,
                connectionState = connectionState,
                statusMessage = statusMessage,
                onStartDiscovery = { viewModel.startDiscovery() },
                onSelectDevice = { viewModel.selectDevice(it) },
                onConnectManual = { viewModel.connectManual(it) }
            )
        }

        ConnectionState.CONNECTING,
        ConnectionState.PAIRING,
        ConnectionState.PAIR_VERIFY -> {
            PairingScreen(
                statusMessage = statusMessage,
                needsPin = needsPin,
                onSubmitPin = { viewModel.submitPin(it) },
                onBack = { viewModel.disconnect() }
            )
        }

        ConnectionState.CONNECTED -> {
            RemoteScreen(
                deviceName = selectedDevice?.name ?: "Apple TV",
                onButton = { viewModel.pressButton(it) },
                onDisconnect = { viewModel.disconnect() }
            )
        }
    }
}
