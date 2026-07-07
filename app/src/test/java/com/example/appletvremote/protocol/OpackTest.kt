package com.example.appletvremote.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class OpackTest {

    @Test
    fun `double values use opack little endian double marker`() {
        val packed = Opack.pack(1000.0)

        assertArrayEquals(
            byteArrayOf(0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x8F.toByte(), 0x40),
            packed
        )
        assertEquals(1000.0, Opack.unpack(packed) as Double, 0.0)
    }

    @Test
    fun `companion touch start payload round trips`() {
        val payload = linkedMapOf<String, Any?>(
            "_height" to 1000.0,
            "_tFl" to 0,
            "_width" to 1000.0
        )

        @Suppress("UNCHECKED_CAST")
        val unpacked = Opack.unpack(Opack.pack(payload)) as Map<String, Any?>

        assertEquals(1000.0, unpacked["_height"] as Double, 0.0)
        assertEquals(0, unpacked["_tFl"])
        assertEquals(1000.0, unpacked["_width"] as Double, 0.0)
    }
}
