package com.example.appletvremote.protocol

import java.io.ByteArrayOutputStream

/**
 * Minimal protobuf encoder/decoder for MRP protocol messages.
 * Field numbers sourced from pyatv and node-appletv implementations.
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
     * Build a CryptoPairingMessage wrapped in ProtocolMessage.
     *
     * ProtocolMessage: field 1=type(51), field 39=CryptoPairingMessage
     * CryptoPairingMessage fields (from pyatv crypto_pairing()):
     *   1 = pairingData (bytes) — TLV8-encoded HAP pairing data
     *   2 = status (varint) — 0
     *   3 = isRetrying (varint/bool) — false
     *   4 = isUsingSystemPairing (varint/bool) — false
     *   5 = state (varint) — 2 for pair-setup, 0 for pair-verify
     */
    fun buildCryptoPairingMessage(pairingData: ByteArray, isPairing: Boolean): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, pairingData))
        inner.write(encodeVarintField(2, 0))     // status = 0
        inner.write(encodeVarintField(3, 0))     // isRetrying = false
        inner.write(encodeVarintField(4, 0))     // isUsingSystemPairing = false
        inner.write(encodeVarintField(5, if (isPairing) 2 else 0))  // state

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_CRYPTO_PAIRING.toLong()))
        outer.write(encodeBytesField(39, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * Build a SendHIDEventMessage wrapped in ProtocolMessage.
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
     * Build a DeviceInfoMessage matching pyatv's device_information().
     * All fields from pyatv/protocols/mrp/messages.py device_information():
     *
     * DeviceInfoMessage fields:
     *   1  = uniqueIdentifier (string)
     *   2  = name (string)
     *   3  = localizedModelName (string) — "iPhone"
     *   4  = systemBuildVersion (string) — iOS build number
     *   5  = applicationBundleIdentifier (string) — "com.apple.TVRemote"
     *   6  = protocolVersion (varint) — 1
     *   7  = applicationBundleVersion (string)
     *   8  = lastSupportedMessageType (varint) — 108
     *   9  = supportsSystemPairing (varint/bool) — true
     *   10 = allowsPairing (varint/bool) — true
     *   11 = systemMediaApplication (string) — "com.apple.TVMusic"
     *   12 = supportsACL (varint/bool) — true
     *   13 = supportsSharedQueue (varint/bool) — true
     *   14 = sharedQueueVersion (varint) — 2
     *   15 = supportsExtendedMotion (varint/bool) — true
     *   16 = deviceClass (varint) — 1 (iPhone)
     *   17 = logicalDeviceCount (varint) — 1
     */
    fun buildDeviceInfoMessage(uniqueId: String, name: String): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, uniqueId.toByteArray()))
        inner.write(encodeBytesField(2, name.toByteArray()))
        inner.write(encodeBytesField(3, "iPhone".toByteArray()))
        inner.write(encodeBytesField(4, "19H12".toByteArray()))
        inner.write(encodeBytesField(5, "com.apple.TVRemote".toByteArray()))
        inner.write(encodeVarintField(6, 1))
        inner.write(encodeBytesField(7, "344.28".toByteArray()))
        inner.write(encodeVarintField(8, 108))
        inner.write(encodeVarintField(9, 1))     // supportsSystemPairing
        inner.write(encodeVarintField(10, 1))    // allowsPairing
        inner.write(encodeBytesField(11, "com.apple.TVMusic".toByteArray()))
        inner.write(encodeVarintField(12, 1))    // supportsACL
        inner.write(encodeVarintField(13, 1))    // supportsSharedQueue
        inner.write(encodeVarintField(14, 2))    // sharedQueueVersion
        inner.write(encodeVarintField(15, 1))    // supportsExtendedMotion
        inner.write(encodeVarintField(16, 1))    // deviceClass = iPhone
        inner.write(encodeVarintField(17, 1))    // logicalDeviceCount

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_DEVICE_INFO.toLong()))
        // DeviceInfoMessage is extension field 17 of ProtocolMessage
        outer.write(encodeBytesField(17, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * Build SetConnectionStateMessage (sent after encryption is enabled).
     */
    fun buildSetConnectionStateMessage(): ByteArray {
        // SetConnectionStateMessage field 1 = state (varint, 1 = connected)
        val inner = ByteArrayOutputStream()
        inner.write(encodeVarintField(1, 1))

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_SET_STATE.toLong()))
        // SetConnectionStateMessage is extension field 50 of ProtocolMessage
        outer.write(encodeBytesField(50, inner.toByteArray()))
        return outer.toByteArray()
    }

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

    const val MSG_TYPE_SEND_COMMAND = 1
    const val MSG_TYPE_SEND_HID_EVENT = 6
    const val MSG_TYPE_DEVICE_INFO = 15
    const val MSG_TYPE_CLIENT_UPDATES_CONFIG = 25
    const val MSG_TYPE_CRYPTO_PAIRING = 51
    const val MSG_TYPE_SET_STATE = 69
}
