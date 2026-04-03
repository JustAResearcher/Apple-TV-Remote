package com.example.appletvremote.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.appletvremote.model.RemoteButton

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteScreen(
    deviceName: String,
    onButton: (RemoteButton) -> Unit,
    onDisconnect: () -> Unit
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(deviceName, maxLines = 1) },
                navigationIcon = {
                    IconButton(onClick = onDisconnect) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Disconnect")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceEvenly
        ) {
            // Top row: Menu and Power
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                RemoteIconButton(
                    icon = Icons.AutoMirrored.Filled.ArrowBack,
                    label = "Menu",
                    onClick = { onButton(RemoteButton.MENU) }
                )
                RemoteIconButton(
                    icon = Icons.Default.Home,
                    label = "Home",
                    onClick = { onButton(RemoteButton.HOME) }
                )
                RemoteIconButton(
                    icon = Icons.Default.PowerSettingsNew,
                    label = "Power",
                    onClick = { onButton(RemoteButton.POWER) }
                )
            }

            // D-Pad with Select button
            DPad(onButton = onButton)

            // Playback controls
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                RemoteIconButton(
                    icon = Icons.Default.SkipPrevious,
                    label = "Previous",
                    onClick = { onButton(RemoteButton.PREVIOUS) }
                )
                RemoteIconButton(
                    icon = Icons.Default.PlayArrow,
                    label = "Play/Pause",
                    onClick = { onButton(RemoteButton.PLAY_PAUSE) },
                    large = true
                )
                RemoteIconButton(
                    icon = Icons.Default.SkipNext,
                    label = "Next",
                    onClick = { onButton(RemoteButton.NEXT) }
                )
            }

            // Volume controls
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment = Alignment.CenterVertically
            ) {
                RemoteIconButton(
                    icon = Icons.Default.VolumeDown,
                    label = "Vol -",
                    onClick = { onButton(RemoteButton.VOLUME_DOWN) }
                )
                Icon(
                    Icons.AutoMirrored.Filled.VolumeUp,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(28.dp)
                )
                RemoteIconButton(
                    icon = Icons.Default.VolumeUp,
                    label = "Vol +",
                    onClick = { onButton(RemoteButton.VOLUME_UP) }
                )
            }
        }
    }
}

@Composable
private fun DPad(onButton: (RemoteButton) -> Unit) {
    Box(
        modifier = Modifier.size(260.dp),
        contentAlignment = Alignment.Center
    ) {
        // Background circle
        Box(
            modifier = Modifier
                .size(260.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant)
        )

        // Up
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .offset(y = 10.dp)
                .size(80.dp, 70.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable { onButton(RemoteButton.UP) },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.KeyboardArrowUp,
                contentDescription = "Up",
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Down
        Box(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .offset(y = (-10).dp)
                .size(80.dp, 70.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable { onButton(RemoteButton.DOWN) },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.KeyboardArrowDown,
                contentDescription = "Down",
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Left
        Box(
            modifier = Modifier
                .align(Alignment.CenterStart)
                .offset(x = 10.dp)
                .size(70.dp, 80.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable { onButton(RemoteButton.LEFT) },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.KeyboardArrowLeft,
                contentDescription = "Left",
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Right
        Box(
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .offset(x = (-10).dp)
                .size(70.dp, 80.dp)
                .clip(RoundedCornerShape(16.dp))
                .clickable { onButton(RemoteButton.RIGHT) },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Default.KeyboardArrowRight,
                contentDescription = "Right",
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        // Select (center)
        Box(
            modifier = Modifier
                .size(90.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
                .clickable { onButton(RemoteButton.SELECT) },
            contentAlignment = Alignment.Center
        ) {
            Text(
                "OK",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@Composable
private fun RemoteIconButton(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    large: Boolean = false
) {
    val size = if (large) 64.dp else 52.dp
    val iconSize = if (large) 36.dp else 28.dp

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.pointerInput(Unit) {
            detectTapGestures(onTap = { onClick() })
        }
    ) {
        Box(
            modifier = Modifier
                .size(size)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant)
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                icon,
                contentDescription = label,
                modifier = Modifier.size(iconSize),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
