package com.example.appletvremote.protocol

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

object Opack {
    fun pack(value: Any?): ByteArray = packValue(value, mutableListOf())

    fun unpack(data: ByteArray): Any? {
        val (value, offset) = unpackValue(data, 0, mutableListOf())
        if (offset != data.size) {
            throw IllegalStateException("Trailing OPACK data: ${data.size - offset} bytes")
        }
        return value
    }

    @Suppress("UNCHECKED_CAST")
    private fun packValue(value: Any?, objectList: MutableList<ByteArray>): ByteArray {
        val packed = when (value) {
            null -> byteArrayOf(0x04)
            is Boolean -> byteArrayOf(if (value) 0x01 else 0x02)
            is Int -> packLong(value.toLong())
            is Long -> packLong(value)
            is Float -> packDouble(value.toDouble())
            is Double -> packDouble(value)
            is String -> packString(value)
            is ByteArray -> packBytes(value)
            is List<*> -> {
                val out = ByteArrayOutputStream()
                val count = value.size
                out.write(0xD0 or minOf(count, 0x0F))
                for (item in value) out.write(packValue(item, objectList))
                if (count >= 0x0F) out.write(0x03)
                out.toByteArray()
            }
            is Map<*, *> -> {
                val out = ByteArrayOutputStream()
                val entries = value.entries.toList()
                out.write(0xE0 or minOf(entries.size, 0x0F))
                for ((key, mapValue) in entries) {
                    out.write(packValue(key as String, objectList))
                    out.write(packValue(mapValue, objectList))
                }
                if (entries.size >= 0x0F) out.write(0x03)
                out.toByteArray()
            }
            else -> throw IllegalArgumentException("Unsupported OPACK type: ${value::class.java.name}")
        }

        if (packed.size <= 1) return packed
        val existing = objectList.indexOfFirst { it.contentEquals(packed) }
        if (existing >= 0) {
            return if (existing < 0x21) {
                byteArrayOf((0xA0 + existing).toByte())
            } else {
                byteArrayOf(0xC1.toByte(), existing.toByte())
            }
        }
        objectList.add(packed)
        return packed
    }

    private fun packLong(value: Long): ByteArray {
        return when {
            value < 0 -> throw IllegalArgumentException("OPACK cannot encode negative integers")
            value < 0x28 -> byteArrayOf((value + 8).toByte())
            value <= 0xFF -> byteArrayOf(0x30, value.toByte())
            value <= 0xFFFF -> byteArrayOf(0x31, value.toByte(), (value shr 8).toByte())
            value <= 0xFFFFFFFFL -> byteArrayOf(
                0x32,
                value.toByte(),
                (value shr 8).toByte(),
                (value shr 16).toByte(),
                (value shr 24).toByte()
            )
            else -> {
                val out = ByteArray(9)
                out[0] = 0x33
                for (i in 0 until 8) out[i + 1] = (value shr (i * 8)).toByte()
                out
            }
        }
    }

    private fun packDouble(value: Double): ByteArray {
        return byteArrayOf(0x36) + ByteBuffer.allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putDouble(value)
            .array()
    }

    private fun packString(value: String): ByteArray {
        val encoded = value.toByteArray()
        return packSized(0x40, 0x61, encoded)
    }

    private fun packBytes(value: ByteArray): ByteArray {
        return packSized(0x70, 0x91, value)
    }

    private fun packSized(shortBase: Int, longBase: Int, value: ByteArray): ByteArray {
        if (value.size <= 0x20) {
            return byteArrayOf((shortBase + value.size).toByte()) + value
        }
        return when {
            value.size <= 0xFF -> byteArrayOf(longBase.toByte(), value.size.toByte()) + value
            value.size <= 0xFFFF -> byteArrayOf(
                (longBase + 1).toByte(),
                value.size.toByte(),
                (value.size shr 8).toByte()
            ) + value
            else -> throw IllegalArgumentException("OPACK value too large")
        }
    }

    private fun unpackValue(
        data: ByteArray,
        startOffset: Int,
        objectList: MutableList<Any?>
    ): Pair<Any?, Int> {
        val marker = data[startOffset].toInt() and 0xFF
        var addToObjects = true
        val result: Pair<Any?, Int> = when {
            marker == 0x01 -> {
                addToObjects = false
                true to startOffset + 1
            }
            marker == 0x02 -> {
                addToObjects = false
                false to startOffset + 1
            }
            marker == 0x04 -> {
                addToObjects = false
                null to startOffset + 1
            }
            marker in 0x08..0x2F -> {
                addToObjects = false
                (marker - 8) to startOffset + 1
            }
            marker == 0x35 -> {
                ByteBuffer.wrap(data, startOffset + 1, 4)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .float to startOffset + 5
            }
            marker == 0x36 -> {
                ByteBuffer.wrap(data, startOffset + 1, 8)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .double to startOffset + 9
            }
            marker and 0xF0 == 0x30 -> {
                val size = 1 shl (marker and 0x0F)
                readLongLE(data, startOffset + 1, size) to startOffset + 1 + size
            }
            marker in 0x40..0x60 -> {
                val length = marker - 0x40
                String(data, startOffset + 1, length) to startOffset + 1 + length
            }
            marker in 0x61..0x64 -> {
                val sizeBytes = marker and 0x0F
                val length = readLongLE(data, startOffset + 1, sizeBytes).toInt()
                val valueOffset = startOffset + 1 + sizeBytes
                String(data, valueOffset, length) to valueOffset + length
            }
            marker in 0x70..0x90 -> {
                val length = marker - 0x70
                data.copyOfRange(startOffset + 1, startOffset + 1 + length) to startOffset + 1 + length
            }
            marker in 0x91..0x94 -> {
                val sizeBytes = 1 shl ((marker and 0x0F) - 1)
                val length = readLongLE(data, startOffset + 1, sizeBytes).toInt()
                val valueOffset = startOffset + 1 + sizeBytes
                data.copyOfRange(valueOffset, valueOffset + length) to valueOffset + length
            }
            marker and 0xF0 == 0xD0 -> {
                addToObjects = false
                val count = marker and 0x0F
                val list = mutableListOf<Any?>()
                var offset = startOffset + 1
                if (count == 0x0F) {
                    while ((data[offset].toInt() and 0xFF) != 0x03) {
                        val (item, next) = unpackValue(data, offset, objectList)
                        list.add(item)
                        offset = next
                    }
                    offset++
                } else {
                    repeat(count) {
                        val (item, next) = unpackValue(data, offset, objectList)
                        list.add(item)
                        offset = next
                    }
                }
                list to offset
            }
            marker and 0xE0 == 0xE0 -> {
                addToObjects = false
                val count = marker and 0x0F
                val map = linkedMapOf<String, Any?>()
                var offset = startOffset + 1
                if (count == 0x0F) {
                    while ((data[offset].toInt() and 0xFF) != 0x03) {
                        val (key, afterKey) = unpackValue(data, offset, objectList)
                        val (value, afterValue) = unpackValue(data, afterKey, objectList)
                        map[key as String] = value
                        offset = afterValue
                    }
                    offset++
                } else {
                    repeat(count) {
                        val (key, afterKey) = unpackValue(data, offset, objectList)
                        val (value, afterValue) = unpackValue(data, afterKey, objectList)
                        map[key as String] = value
                        offset = afterValue
                    }
                }
                map to offset
            }
            marker in 0xA0..0xC0 -> {
                objectList[marker - 0xA0] to startOffset + 1
            }
            marker in 0xC1..0xC4 -> {
                val sizeBytes = marker - 0xC0
                val index = readLongLE(data, startOffset + 1, sizeBytes).toInt()
                objectList[index] to startOffset + 1 + sizeBytes
            }
            else -> throw IllegalStateException("Unsupported OPACK marker: 0x${marker.toString(16)}")
        }

        if (addToObjects && !objectList.any { opackEquals(it, result.first) }) {
            objectList.add(result.first)
        }
        return result
    }

    private fun opackEquals(left: Any?, right: Any?): Boolean {
        return if (left is ByteArray && right is ByteArray) {
            left.contentEquals(right)
        } else {
            left == right
        }
    }

    private fun readLongLE(data: ByteArray, offset: Int, length: Int): Long {
        var value = 0L
        for (i in 0 until length) {
            value = value or ((data[offset + i].toLong() and 0xFF) shl (i * 8))
        }
        return value
    }
}
