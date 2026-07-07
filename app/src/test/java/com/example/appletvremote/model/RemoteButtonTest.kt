package com.example.appletvremote.model

import org.junit.Assert.assertEquals
import org.junit.Test

class RemoteButtonTest {

    @Test
    fun `navigation keys match media remote HID usages`() {
        assertEquals(0x8C, RemoteButton.UP.usage)
        assertEquals(0x8D, RemoteButton.DOWN.usage)
        assertEquals(0x8B, RemoteButton.LEFT.usage)
        assertEquals(0x8A, RemoteButton.RIGHT.usage)
        assertEquals(0x89, RemoteButton.SELECT.usage)
        assertEquals(0x86, RemoteButton.MENU.usage)
    }

    @Test
    fun `system keys match media remote HID usages`() {
        assertEquals(0x0C, RemoteButton.HOME.usagePage)
        assertEquals(0x40, RemoteButton.HOME.usage)
        assertEquals(0x01, RemoteButton.POWER.usagePage)
        assertEquals(0x82, RemoteButton.POWER.usage)
    }

    @Test
    fun `common keys map to companion hid commands`() {
        assertEquals(1, RemoteButton.UP.companionCommand)
        assertEquals(2, RemoteButton.DOWN.companionCommand)
        assertEquals(3, RemoteButton.LEFT.companionCommand)
        assertEquals(4, RemoteButton.RIGHT.companionCommand)
        assertEquals(5, RemoteButton.MENU.companionCommand)
        assertEquals(6, RemoteButton.SELECT.companionCommand)
        assertEquals(14, RemoteButton.PLAY_PAUSE.companionCommand)
        assertEquals(8, RemoteButton.VOLUME_UP.companionCommand)
        assertEquals(9, RemoteButton.VOLUME_DOWN.companionCommand)
    }
}
