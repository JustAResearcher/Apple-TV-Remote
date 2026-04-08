package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Manages the TCP connection to Apple TV for MRP protocol communication.
 *
 * MRP uses plain TCP (confirmed by pyatv source). Encryption is handled
 * at the application layer using ChaCha20-Poly1305 after pair-verify.
 *
 * Wire format: varint(length) + [optional chacha20 encrypt](protobuf bytes)
 */
class MrpConnection {
    companion object {
        private const val TAG = "MrpConnection"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 30_000
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    var cipher: MrpCipher? = null
    var isConnected = false
        private set

    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
        sock.soTimeout = READ_TIMEOUT
        sock.tcpNoDelay = true
        // Enable TCP keepalive (matches pyatv's tcp_keepalive)
        sock.keepAlive = true
        socket = sock
        inputStream = sock.getInputStream()
        outputStream = sock.getOutputStream()
        isConnected = true
        Log.d(TAG, "Connected to $host:$port (plain TCP)")
    }

    fun disconnect() {
        try {
            isConnected = false
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        inputStream = null
        outputStream = null
        cipher = null
    }

    /**
     * Send: varint(length) + data
     * If chacha is enabled, data is encrypted first, then length-prefixed.
     * (Matches pyatv: encrypt first, then write_variant(len) + encrypted)
     */
    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        val payload: ByteArray
        val encCipher = cipher
        if (encCipher != null) {
            payload = encCipher.encrypt(protobufData)
        } else {
            payload = protobufData
        }

        val frame = encodeVarint(payload.size) + payload
        os.write(frame)
        os.flush()
        Log.d(TAG, "Sent: ${protobufData.size} bytes proto, ${payload.size} bytes wire (encrypted=${encCipher != null})")
    }

    /**
     * Receive: read varint length, read that many bytes, decrypt if needed.
     * (Matches pyatv: read_variant -> extract bytes -> decrypt if chacha)
     */
    suspend fun receiveMessage(): ByteArray = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")

        val length = readVarint(ins)
        if (length <= 0 || length > 1_000_000) {
            throw IllegalStateException("Invalid message length: $length")
        }

        val data = readExact(ins, length.toInt())
        Log.d(TAG, "Recv: $length bytes from wire")

        val encCipher = cipher
        if (encCipher != null) {
            encCipher.decrypt(data)
        } else {
            data
        }
    }

    private fun encodeVarint(value: Int): ByteArray {
        if (value < 0x80) return byteArrayOf(value.toByte())
        val result = mutableListOf<Byte>()
        var v = value
        while (v > 0x7F) {
            result.add(((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        result.add((v and 0x7F).toByte())
        return result.toByteArray()
    }

    private fun readVarint(input: InputStream): Long {
        var result = 0L
        var shift = 0
        while (true) {
            val b = input.read()
            if (b < 0) throw java.io.IOException("Connection closed while reading varint")
            result = result or ((b.toLong() and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 35) throw IllegalStateException("Varint too long")
        }
        return result
    }

    private fun readExact(input: InputStream, length: Int): ByteArray {
        val buffer = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(buffer, offset, length - offset)
            if (read < 0) throw java.io.IOException("Connection closed (read $offset/$length)")
            offset += read
        }
        return buffer
    }
}
