package com.example.appletvremote.protocol

import java.io.ByteArrayOutputStream

/**
 * Minimal protobuf encoder/decoder for MRP protocol messages.
 *
 * Field numbers from the actual .proto files in pyatv:
 *   ProtocolMessage extensions:
 *     13 = sendHIDEventMessage
 *     20 = deviceInfoMessage
 *     39 = cryptoPairingMessage
 *     42 = setConnectionStateMessage
 */
object ProtobufHelper {

    private const val WIRE_VARINT = 0
    private const val WIRE_LENGTH_DELIMITED = 2

    // ProtocolMessage extension field numbers (from .proto files)
    private const val EXT_SEND_HID_EVENT = 13
    private const val EXT_DEVICE_INFO = 20
    private const val EXT_CRYPTO_PAIRING = 39
    private const val EXT_SET_CONNECTION_STATE = 42

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

    fun encodeBoolField(fieldNumber: Int, value: Boolean): ByteArray {
        return encodeVarintField(fieldNumber, if (value) 1L else 0L)
    }

    fun encodeBytesField(fieldNumber: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodeTag(fieldNumber, WIRE_LENGTH_DELIMITED))
        out.write(encodeVarint(value.size.toLong()))
        out.write(value)
        return out.toByteArray()
    }

    fun encodeStringField(fieldNumber: Int, value: String): ByteArray {
        return encodeBytesField(fieldNumber, value.toByteArray())
    }

    /**
     * CryptoPairingMessage (extension field 39):
     *   1 = pairingData (bytes)
     *   2 = status (int32)
     *   3 = isRetrying (bool)
     *   4 = isUsingSystemPairing (bool)
     *   5 = state (int32) — 2 for pair-setup, 0 for pair-verify
     */
    fun buildCryptoPairingMessage(pairingData: ByteArray, isPairing: Boolean): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, pairingData))
        inner.write(encodeVarintField(2, 0))     // status = 0
        inner.write(encodeBoolField(3, false))   // isRetrying
        inner.write(encodeBoolField(4, false))   // isUsingSystemPairing
        inner.write(encodeVarintField(5, if (isPairing) 2 else 0))

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_CRYPTO_PAIRING.toLong()))
        outer.write(encodeBytesField(EXT_CRYPTO_PAIRING, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * SendHIDEventMessage (extension field 13):
     *   1 = hidEventData (bytes) — 44 bytes
     *   (no hidDescriptorID field — that was wrong)
     */
    fun buildSendHIDEventMessage(usagePage: Int, usage: Int, down: Boolean): ByteArray {
        val hidData = ByteArray(44)
        writeUint32LE(hidData, 4, usagePage)
        writeUint32LE(hidData, 8, usage)
        writeUint32LE(hidData, 12, if (down) 1 else 0)

        val inner = ByteArrayOutputStream()
        inner.write(encodeBytesField(1, hidData))

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_SEND_HID_EVENT.toLong()))
        outer.write(encodeBytesField(EXT_SEND_HID_EVENT, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * DeviceInfoMessage (extension field 20):
     * Field numbers from DeviceInfoMessage.proto:
     *   1  = uniqueIdentifier (string)
     *   2  = name (string, required)
     *   3  = localizedModelName (string)
     *   4  = systemBuildVersion (string)
     *   5  = applicationBundleIdentifier (string)
     *   6  = applicationBundleVersion (string)
     *   7  = protocolVersion (int32)
     *   8  = lastSupportedMessageType (uint32)
     *   9  = supportsSystemPairing (bool)
     *   10 = allowsPairing (bool)
     *   12 = systemMediaApplication (string)
     *   13 = supportsACL (bool)
     *   14 = supportsSharedQueue (bool)
     *   15 = supportsExtendedMotion (bool)
     *   17 = sharedQueueVersion (uint32)
     *   21 = deviceClass (enum, 1=iPhone)
     *   22 = logicalDeviceCount (uint32)
     */
    fun buildDeviceInfoMessage(uniqueId: String, name: String): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeStringField(1, uniqueId))
        inner.write(encodeStringField(2, name))
        inner.write(encodeStringField(3, "iPhone"))
        inner.write(encodeStringField(4, "19H12"))
        inner.write(encodeStringField(5, "com.apple.TVRemote"))
        inner.write(encodeStringField(6, "344.28"))
        inner.write(encodeVarintField(7, 1))     // protocolVersion
        inner.write(encodeVarintField(8, 108))   // lastSupportedMessageType
        inner.write(encodeBoolField(9, true))    // supportsSystemPairing
        inner.write(encodeBoolField(10, true))   // allowsPairing
        inner.write(encodeStringField(12, "com.apple.TVMusic"))
        inner.write(encodeBoolField(13, true))   // supportsACL
        inner.write(encodeBoolField(14, true))   // supportsSharedQueue
        inner.write(encodeBoolField(15, true))   // supportsExtendedMotion
        inner.write(encodeVarintField(17, 2))    // sharedQueueVersion
        inner.write(encodeVarintField(21, 1))    // deviceClass = iPhone
        inner.write(encodeVarintField(22, 1))    // logicalDeviceCount

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_DEVICE_INFO.toLong()))
        outer.write(encodeBytesField(EXT_DEVICE_INFO, inner.toByteArray()))
        return outer.toByteArray()
    }

    /**
     * SetConnectionStateMessage (extension field 42):
     *   1 = state (enum: 0=None, 1=Connecting, 2=Connected, 3=Disconnected)
     */
    fun buildSetConnectionStateMessage(): ByteArray {
        val inner = ByteArrayOutputStream()
        inner.write(encodeVarintField(1, 2)) // Connected

        val outer = ByteArrayOutputStream()
        outer.write(encodeVarintField(1, MSG_TYPE_SET_STATE.toLong()))
        outer.write(encodeBytesField(EXT_SET_CONNECTION_STATE, inner.toByteArray()))
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

    // MRP message type constants
    const val MSG_TYPE_SEND_COMMAND = 1
    const val MSG_TYPE_SEND_HID_EVENT = 6
    const val MSG_TYPE_DEVICE_INFO = 15
    const val MSG_TYPE_CLIENT_UPDATES_CONFIG = 25
    const val MSG_TYPE_CRYPTO_PAIRING = 51
    const val MSG_TYPE_SET_STATE = 69
}
