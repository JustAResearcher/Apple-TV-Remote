package com.example.appletvremote.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.appletvremote.model.RemoteButton
import kotlin.math.abs

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

            // Touchpad: swipe to navigate, tap to select
            Touchpad(onButton = onButton)

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
private fun Touchpad(onButton: (RemoteButton) -> Unit) {
    val swipeThreshold = with(LocalDensity.current) { 40.dp.toPx() }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(260.dp)
            .clip(RoundedCornerShape(32.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .pointerInput(swipeThreshold) {
                var totalDrag = Offset.Zero
                detectDragGestures(
                    onDragStart = { totalDrag = Offset.Zero },
                    onDragEnd = {
                        val button = when {
                            abs(totalDrag.x) < swipeThreshold &&
                                abs(totalDrag.y) < swipeThreshold -> null
                            abs(totalDrag.x) > abs(totalDrag.y) ->
                                if (totalDrag.x > 0) RemoteButton.RIGHT else RemoteButton.LEFT
                            else ->
                                if (totalDrag.y > 0) RemoteButton.DOWN else RemoteButton.UP
                        }
                        button?.let(onButton)
                        totalDrag = Offset.Zero
                    },
                    onDragCancel = { totalDrag = Offset.Zero },
                    onDrag = { change, dragAmount ->
                        change.consume()
                        totalDrag += dragAmount
                    }
                )
            }
            .clickable { onButton(RemoteButton.SELECT) },
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Icon(
                Icons.Default.TouchApp,
                contentDescription = null,
                modifier = Modifier.size(40.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(
                "Touchpad",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Swipe to navigate  •  Tap to select",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
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
        horizontalAlignment = Alignment.CenterHorizontally
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
