package com.example.appletvremote.protocol

import java.io.ByteArrayOutputStream

/**
 * Minimal protobuf encoder/decoder for MRP protocol messages.
 *
 * Key field numbers from the actual .proto spec:
 *   ProtocolMessage.type = field 1 (varint)
 *   ProtocolMessage.cryptoPairingMessage = field 39 (NOT 46!)
 *   ProtocolMessage.sendHIDEventMessage = field 8
 *   ProtocolMessage.deviceInfoMessage = field 17
 *
 *   CryptoPairingMessage.pairingData = field 1 (bytes)
 *   CryptoPairingMessage.status = field 2 (varint, optional)
 */
object ProtobufHelper {

    private const val WIRE_VARINT = 0
    private const val WIRE_LENGTH_DELIMITED = 2

    fun encodeVarint(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        while (v and 0x7F.inv() != 0L) {
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
        out.write((v and 0x7F).toInt())
        return out.toByteArray()
    }

    fun encodeTag(fieldNumber: Int, wireType: Int): ByteArray {
        return encodeVarint(((fieldNumber shl 3) or wireType).toLong())
    }

    fun encodeVarintField(fieldNumber: Int, value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeTag(fieldNumber, WIRE_VARINT))
        out.write(encodeVarint(value))
        return out.toByteArray()
    }

    fun encodeBytesField(fieldNumber: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeTag(fieldNumber, WIRE_LENGTH_DELIMITED))
        out.write(encodeVarint(value.size.toLong()))
        out.write(value)
        return out.toByteArray()
    }

    /**
     * Build a ProtocolMessage for CryptoPairing.
     * ProtocolMessage: field 1 = type (varint), field 39 = CryptoPairingMessage
     * CryptoPairingMessage: field 1 = pairingData (bytes), field 2 = status (varint)
     */
    fun buildCryptoPairingMessage(pairingData: ByteArray): ByteArray {
        // Inner CryptoPairingMessage: field 1 = pairingData, field 2 = status 0
        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, pairingData))
        inner.write(encodeVarintField(2, 0)) // status = 0

        // Outer ProtocolMessage: field 1 = type, field 39 = cryptoPairingMessage
        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_CRYPTO_PAIRING.toLong()))
        outer.write(encodeBytesField(39, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * Build a ProtocolMessage for SendHIDEvent.
     */
    fun buildSendHIDEventMessage(usagePage: Int, usage: Int, down: Boolean): ByteArray {
        val hidData = ByteArray(44)
        writeUint32LE(hidData, 4, usagePage)
        writeUint32LE(hidData, 8, usage)
        writeUint32LE(hidData, 12, if (down) 1 else 0)

        val inner = ByteArrayOutputStream()
        inner.write(encodeVarintField(1, 0))
        inner.write(encodeBytesField(2, hidData))

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_SEND_HID_EVENT.toLong()))
        outer.write(encodeBytesField(8, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * Build a DeviceInfoMessage.
     * DeviceInfoMessage fields:
     *   1 = uniqueIdentifier (string)
     *   2 = name (string)
     *   3 = localizedModelName (string, optional)
     *   4 = systemBuildVersion (string, optional)
     *   5 = applicationBundleIdentifier (string, optional)
     *   6 = protocolVersion (varint, optional)
     *   9 = systemMediaApplication (string, optional)
     */
    fun buildDeviceInfoMessage(uniqueId: String, name: String): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, uniqueId.toByteArray()))
        inner.write(encodeBytesField(2, name.toByteArray()))
        inner.write(encodeBytesField(3, "Android".toByteArray()))
        inner.write(encodeBytesField(4, "1.0".toByteArray()))
        inner.write(encodeBytesField(5, "com.example.appletvremote".toByteArray()))
        inner.write(encodeVarintField(6, 1))

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_DEVICE_INFO.toLong()))
        outer.write(encodeBytesField(17, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * Parse a ProtocolMessage and extract fields.
     */
    fun parseMessage(data: ByteArray): Map<Int, Any> {
        val result = mutableMapOf<Int, Any>()
        var offset = 0
        while (offset < data.size) {
            val (tag, newOffset) = decodeVarint(data, offset)
            offset = newOffset
            val fieldNumber = (tag shr 3).toInt()
            val wireType = (tag and 0x07).toInt()

            when (wireType) {
                WIRE_VARINT -> {
                    val (value, nextOffset) = decodeVarint(data, offset)
                    result[fieldNumber] = value
                    offset = nextOffset
                }
                WIRE_LENGTH_DELIMITED -> {
                    val (length, lenOffset) = decodeVarint(data, offset)
                    offset = lenOffset
                    val end = offset + length.toInt()
                    if (end <= data.size) {
                        result[fieldNumber] = data.copyOfRange(offset, end)
                    }
                    offset = end
                }
                else -> break
            }
        }
        return result
    }

    fun decodeVarint(data: ByteArray, startOffset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var offset = startOffset
        while (offset < data.size) {
            val b = data[offset].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            offset++
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result to offset
    }

    private fun writeUint32LE(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value and 0xFF).toByte()
        data[offset + 1] = ((value shr 8) and 0xFF).toByte()
        data[offset + 2] = ((value shr 16) and 0xFF).toByte()
        data[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

    // MRP message type constants
    const val MSG_TYPE_SEND_COMMAND = 1
    const val MSG_TYPE_SEND_HID_EVENT = 6
    const val MSG_TYPE_DEVICE_INFO = 15
    const val MSG_TYPE_CLIENT_UPDATES_CONFIG = 25
    const val MSG_TYPE_CRYPTO_PAIRING = 51
    const val MSG_TYPE_SET_STATE = 69
}
