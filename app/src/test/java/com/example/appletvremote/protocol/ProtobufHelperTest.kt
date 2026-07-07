package com.example.appletvremote.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtobufHelperTest {

    @Test
    fun `device info uses mrp type and extension`() {
        val message = ProtobufHelper.buildDeviceInfoMessage("client-id", "Android Remote")
        val outer = ProtobufHelper.parseMessage(message)

        assertEquals(ProtobufHelper.MSG_TYPE_DEVICE_INFO.toLong(), outer[1])
        assertNotNull("DeviceInfo should include a request identifier", outer[2])
        assertNotNull("DeviceInfo extension should be present", outer[20])
        assertNotNull("Unique protocol message id should be present", outer[85])

        val inner = ProtobufHelper.parseMessage(outer[20] as ByteArray)
        assertEquals("client-id", String(inner[1] as ByteArray))
        assertEquals("Android Remote", String(inner[2] as ByteArray))
        assertEquals(1L, inner[7])
        assertEquals(108L, inner[8])
    }

    @Test
    fun `crypto pairing uses mrp crypto type and state`() {
        val pairingData = byteArrayOf(0x06, 0x01, 0x01)
        val message = ProtobufHelper.buildCryptoPairingMessage(pairingData, isPairing = true)
        val outer = ProtobufHelper.parseMessage(message)

        assertEquals(ProtobufHelper.MSG_TYPE_CRYPTO_PAIRING.toLong(), outer[1])
        val inner = ProtobufHelper.parseMessage(outer[39] as ByteArray)

        assertArrayEquals(pairingData, inner[1] as ByteArray)
        assertEquals(0L, inner[2])
        assertEquals(0L, inner[3])
        assertEquals(0L, inner[4])
        assertEquals(2L, inner[5])
    }

    @Test
    fun `pair verify crypto message uses state zero`() {
        val message = ProtobufHelper.buildCryptoPairingMessage(byteArrayOf(0x06, 0x01, 0x01), isPairing = false)
        val outer = ProtobufHelper.parseMessage(message)
        val inner = ProtobufHelper.parseMessage(outer[39] as ByteArray)

        assertEquals(ProtobufHelper.MSG_TYPE_CRYPTO_PAIRING.toLong(), outer[1])
        assertEquals(0L, inner[5])
    }

    @Test
    fun `set connection state uses connected message`() {
        val message = ProtobufHelper.buildSetConnectionStateMessage()
        val outer = ProtobufHelper.parseMessage(message)

        assertEquals(ProtobufHelper.MSG_TYPE_SET_CONNECTION_STATE.toLong(), outer[1])
        val inner = ProtobufHelper.parseMessage(outer[42] as ByteArray)

        assertEquals(2L, inner[1])
    }

    @Test
    fun `hid event uses pyatv compatible keyboard event payload`() {
        val message = ProtobufHelper.buildSendHIDEventMessage(usagePage = 1, usage = 0x8C, down = true)
        val outer = ProtobufHelper.parseMessage(message)

        assertEquals(ProtobufHelper.MSG_TYPE_SEND_HID_EVENT.toLong(), outer[1])
        val inner = ProtobufHelper.parseMessage(outer[13] as ByteArray)
        val hidData = inner[1] as ByteArray

        assertEquals(60, hidData.size)
        assertArrayEquals(byteArrayOf(0x43, 0x89.toByte(), 0x22, 0xcf.toByte()), hidData.copyOfRange(0, 4))
        assertArrayEquals(byteArrayOf(0x00, 0x01), hidData.copyOfRange(43, 45))
        assertArrayEquals(byteArrayOf(0x00, 0x8c.toByte()), hidData.copyOfRange(45, 47))
        assertArrayEquals(byteArrayOf(0x00, 0x01), hidData.copyOfRange(47, 49))
    }

    @Test
    fun `protobuf parser keeps expected generated ids as strings`() {
        val message = ProtobufHelper.buildSetConnectionStateMessage()
        val outer = ProtobufHelper.parseMessage(message)

        assertTrue((outer[85] as ByteArray).isNotEmpty())
    }
}
