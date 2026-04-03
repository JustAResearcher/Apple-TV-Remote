package com.example.appletvremote.protocol

import java.io.ByteArrayOutputStream

/**
 * TLV8 encoding/decoding used by HAP (HomeKit Accessory Protocol) pairing.
 * Each TLV entry: 1 byte type, 1 byte length (max 255), N bytes value.
 * Values > 255 bytes are split across consecutive entries of the same type.
 */
object TlvType {
    const val METHOD = 0x00
    const val IDENTIFIER = 0x01
    const val SALT = 0x02
    const val PUBLIC_KEY = 0x03
    const val PROOF = 0x04
    const val ENCRYPTED_DATA = 0x05
    const val STATE = 0x06
    const val ERROR = 0x07
    const val SIGNATURE = 0x0A
}

class TlvEncoder {
    private val entries = mutableListOf<Pair<Int, ByteArray>>()

    fun add(type: Int, value: ByteArray): TlvEncoder {
        entries.add(type to value)
        return this
    }

    fun add(type: Int, value: Int): TlvEncoder {
        entries.add(type to byteArrayOf(value.toByte()))
        return this
    }

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        for ((type, value) in entries) {
            if (value.isEmpty()) {
                out.write(type)
                out.write(0)
                continue
            }
            var offset = 0
            while (offset < value.size) {
                val chunkSize = minOf(255, value.size - offset)
                out.write(type)
                out.write(chunkSize)
                out.write(value, offset, chunkSize)
                offset += chunkSize
            }
        }
        return out.toByteArray()
    }
}

class TlvDecoder(private val data: ByteArray) {
    fun decode(): Map<Int, ByteArray> {
        val result = mutableMapOf<Int, ByteArrayOutputStream>()
        var offset = 0
        while (offset + 1 < data.size) {
            val type = data[offset].toInt() and 0xFF
            val length = data[offset + 1].toInt() and 0xFF
            offset += 2
            val stream = result.getOrPut(type) { ByteArrayOutputStream() }
            if (length > 0 && offset + length <= data.size) {
                stream.write(data, offset, length)
            }
            offset += length
        }
        return result.mapValues { it.value.toByteArray() }
    }
}
