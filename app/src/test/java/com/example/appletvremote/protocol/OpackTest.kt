package com.example.appletvremote.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.UUID

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

    @Test
    fun `uuid values use opack uuid marker`() {
        val uuid = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val packed = Opack.pack(uuid)

        assertArrayEquals(
            byteArrayOf(
                0x05,
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,
                0x66,
                0x77,
                0x88.toByte(),
                0x99.toByte(),
                0xAA.toByte(),
                0xBB.toByte(),
                0xCC.toByte(),
                0xDD.toByte(),
                0xEE.toByte(),
                0xFF.toByte()
            ),
            packed
        )
        assertEquals(uuid, Opack.unpack(packed))
    }

    @Test
    fun `absolute time marker decodes as little endian long`() {
        val packed = byteArrayOf(0x06, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01)

        assertEquals(0x0102030405060708L, Opack.unpack(packed))
    }
}
