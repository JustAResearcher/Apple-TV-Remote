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
}
