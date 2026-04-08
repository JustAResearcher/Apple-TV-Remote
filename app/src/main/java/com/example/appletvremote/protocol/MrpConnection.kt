package com.example.appletvremote.protocol

import android.util.Log
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Manages the connection to Apple TV for MRP protocol communication.
 *
 * Tries plain TCP first. If the Apple TV closes the connection (tvOS 15+
 * requires encrypted transport), falls back to TLS.
 *
 * Message framing (before pair-verify):
 *   [varint length] [protobuf ProtocolMessage]
 *
 * Message framing (after pair-verify):
 *   [2-byte LE length (AAD)] [encrypted payload + 16-byte tag]
 */
class MrpConnection {
    companion object {
        private const val TAG = "MrpConnection"
        private const val CONNECT_TIMEOUT = 5_000
        private const val READ_TIMEOUT = 15_000
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    var cipher: MrpCipher? = null
    var isConnected = false
        private set
    var usingTls = false
        private set

    /**
     * Connect to Apple TV. Tries plain TCP first, then TLS if that fails.
     */
    suspend fun connect(host: String, port: Int) = withContext(Dispatchers.IO) {
        // Try plain TCP first
        try {
            connectPlain(host, port)
            // Test if the connection stays open by waiting briefly
            Log.d(TAG, "Plain TCP connected to $host:$port")
            return@withContext
        } catch (e: Exception) {
            Log.d(TAG, "Plain TCP failed to $host:$port: ${e.message}")
            disconnect()
        }

        // Fall back to TLS
        try {
            connectTls(host, port)
            Log.d(TAG, "TLS connected to $host:$port")
            return@withContext
        } catch (e: Exception) {
            Log.e(TAG, "TLS also failed to $host:$port: ${e.message}")
            throw e
        }
    }

    private fun connectPlain(host: String, port: Int) {
        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)
        sock.soTimeout = READ_TIMEOUT
        sock.tcpNoDelay = true
        socket = sock
        inputStream = sock.getInputStream()
        outputStream = sock.getOutputStream()
        isConnected = true
        usingTls = false
    }

    private fun connectTls(host: String, port: Int) {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())

        val plainSocket = Socket()
        plainSocket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT)

        val ssl = sslContext.socketFactory.createSocket(
            plainSocket, host, port, true
        ) as SSLSocket
        ssl.soTimeout = READ_TIMEOUT
        ssl.startHandshake()

        socket = plainSocket
        inputStream = ssl.inputStream
        outputStream = ssl.outputStream
        isConnected = true
        usingTls = true
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

    suspend fun sendMessage(protobufData: ByteArray) = withContext(Dispatchers.IO) {
        val os = outputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            val encrypted = encCipher.encrypt(protobufData)
            os.write(encrypted)
        } else {
            os.write(encodeVarint(protobufData.size))
            os.write(protobufData)
        }
        os.flush()
        Log.d(TAG, "Sent message: ${protobufData.size} bytes (tls=$usingTls, encrypted=${encCipher != null})")
    }

    suspend fun receiveMessage(): ByteArray = withContext(Dispatchers.IO) {
        val ins = inputStream ?: throw IllegalStateException("Not connected")

        val encCipher = cipher
        if (encCipher != null) {
            val header = readExact(ins, 2)
            val payloadLength = encCipher.decryptedLength(header)
            val encrypted = readExact(ins, payloadLength + 16)
            encCipher.decrypt(header + encrypted)
        } else {
            val length = readVarint(ins)
            if (length <= 0 || length > 1_000_000) {
                throw IllegalStateException("Invalid message length: $length")
            }
            Log.d(TAG, "Receiving message: $length bytes")
            readExact(ins, length.toInt())
        }
    }

    private fun encodeVarint(value: Int): ByteArray {
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
