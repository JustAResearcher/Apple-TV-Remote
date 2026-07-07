package com.example.appletvremote.protocol

import com.example.appletvremote.model.PairingCredentials
import com.example.appletvremote.model.RemoteButton
import kotlinx.coroutines.delay
import java.util.UUID

class CompanionRemote(private val connection: CompanionConnection) {
    companion object {
        private const val PAIRING_DATA_KEY = "_pd"
        private const val SRP_SALT = ""
        private const val SRP_OUTPUT_INFO = "ClientEncrypt-main"
        private const val SRP_INPUT_INFO = "ServerEncrypt-main"
        private const val MEDIA_CONTROL_GET_VOLUME = 5
        private const val MEDIA_CONTROL_SET_VOLUME = 6
        private const val VOLUME_STEP = 0.05
    }

    private val srp = SrpClient()
    private var clientId = UUID.randomUUID().toString()
    private var edKeyPair: CryptoHelper.Ed25519KeyPair? = null
    private var xid = 1
    private var remoteSessionId: Long = 0

    suspend fun connect(host: String, port: Int) {
        connection.connect(host, port)
    }

    fun disconnect() {
        connection.disconnect()
    }

    suspend fun startPairing(): Pair<ByteArray, ByteArray> {
        edKeyPair = CryptoHelper.generateEd25519KeyPair()
        val tlv = TlvEncoder()
            .add(TlvType.METHOD, 0)
            .add(TlvType.STATE, 1)
            .encode()
        val response = exchangeAuth(
            CompanionFrameType.PS_START,
            CompanionFrameType.PS_NEXT,
            linkedMapOf(
                PAIRING_DATA_KEY to tlv,
                "_pwTy" to 1
            )
        )
        val responseTlv = pairingTlv(response)
        val salt = responseTlv[TlvType.SALT] ?: throw IllegalStateException("No salt in Companion M2")
        val serverPubKey = responseTlv[TlvType.PUBLIC_KEY]
            ?: throw IllegalStateException("No public key in Companion M2")
        return salt to serverPubKey
    }

    suspend fun finishPairing(pin: String, salt: ByteArray, serverPublicKey: ByteArray): PairingCredentials {
        val ed = edKeyPair ?: throw IllegalStateException("No Companion pairing key")
        srp.generateCredentials(ed.privateKey)
        val proof = srp.processChallenge("Pair-Setup", pin, salt, serverPublicKey)

        var response = exchangeAuth(
            CompanionFrameType.PS_NEXT,
            CompanionFrameType.PS_NEXT,
            linkedMapOf(
                PAIRING_DATA_KEY to TlvEncoder()
                    .add(TlvType.STATE, 3)
                    .add(TlvType.PUBLIC_KEY, srp.publicKey)
                    .add(TlvType.PROOF, proof)
                    .encode(),
                "_pwTy" to 1
            )
        )
        var responseTlv = pairingTlv(response)
        val serverProof = responseTlv[TlvType.PROOF]
            ?: throw IllegalStateException("No Companion server proof in M4")
        if (!srp.verifyServerProof(serverProof)) {
            throw IllegalStateException("Companion server proof verification failed")
        }

        val sessionKey = srp.getSessionKey()
        val signingKey = CryptoHelper.hkdfSha512(
            sessionKey,
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
            32
        )
        val idBytes = clientId.toByteArray()
        val signature = CryptoHelper.ed25519Sign(ed.privateKey, signingKey + idBytes + ed.publicKey)
        val innerTlv = TlvEncoder()
            .add(TlvType.IDENTIFIER, idBytes)
            .add(TlvType.PUBLIC_KEY, ed.publicKey)
            .add(TlvType.SIGNATURE, signature)
            .encode()
        val encryptKey = CryptoHelper.hkdfSha512(
            sessionKey,
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            32
        )
        val nonce = ByteArray(12)
        "PS-Msg05".toByteArray().copyInto(nonce, 4)
        val encryptedData = CryptoHelper.chaCha20Poly1305Encrypt(encryptKey, nonce, innerTlv)

        response = exchangeAuth(
            CompanionFrameType.PS_NEXT,
            CompanionFrameType.PS_NEXT,
            linkedMapOf(
                PAIRING_DATA_KEY to TlvEncoder()
                    .add(TlvType.STATE, 5)
                    .add(TlvType.ENCRYPTED_DATA, encryptedData)
                    .encode(),
                "_pwTy" to 1
            )
        )
        responseTlv = pairingTlv(response)
        val encryptedServerData = responseTlv[TlvType.ENCRYPTED_DATA]
            ?: throw IllegalStateException("No Companion encrypted data in M6")
        val m6Nonce = ByteArray(12)
        "PS-Msg06".toByteArray().copyInto(m6Nonce, 4)
        val decrypted = CryptoHelper.chaCha20Poly1305Decrypt(encryptKey, m6Nonce, encryptedServerData)
        val serverTlv = TlvDecoder(decrypted).decode()
        val peerIdentifier = serverTlv[TlvType.IDENTIFIER]
            ?: throw IllegalStateException("No Companion peer identifier in M6")
        val peerPublicKey = serverTlv[TlvType.PUBLIC_KEY]
            ?: throw IllegalStateException("No Companion peer public key in M6")

        return PairingCredentials(
            deviceId = "",
            clientId = clientId,
            clientPrivateKey = ed.privateKey,
            clientPublicKey = ed.publicKey,
            peerPublicKey = peerPublicKey,
            peerIdentifier = peerIdentifier
        )
    }

    suspend fun pairVerify(credentials: PairingCredentials) {
        val x25519 = CryptoHelper.generateX25519KeyPair()
        var response = exchangeAuth(
            CompanionFrameType.PV_START,
            CompanionFrameType.PV_NEXT,
            linkedMapOf(
                PAIRING_DATA_KEY to TlvEncoder()
                    .add(TlvType.STATE, 1)
                    .add(TlvType.PUBLIC_KEY, x25519.publicKey)
                    .encode(),
                "_auTy" to 4
            )
        )
        var responseTlv = pairingTlv(response)
        val serverPublicKey = responseTlv[TlvType.PUBLIC_KEY]
            ?: throw IllegalStateException("No Companion pair-verify public key")
        val encryptedData = responseTlv[TlvType.ENCRYPTED_DATA]
            ?: throw IllegalStateException("No Companion pair-verify encrypted data")
        val sharedSecret = CryptoHelper.x25519SharedSecret(x25519.privateKey, serverPublicKey)
        val sessionKey = CryptoHelper.hkdfSha512(
            sharedSecret,
            "Pair-Verify-Encrypt-Salt",
            "Pair-Verify-Encrypt-Info",
            32
        )

        val m2Nonce = ByteArray(12)
        "PV-Msg02".toByteArray().copyInto(m2Nonce, 4)
        val decryptedTlv = TlvDecoder(
            CryptoHelper.chaCha20Poly1305Decrypt(sessionKey, m2Nonce, encryptedData)
        ).decode()
        val peerIdentifier = decryptedTlv[TlvType.IDENTIFIER]
            ?: throw IllegalStateException("No Companion pair-verify identifier")
        val peerSignature = decryptedTlv[TlvType.SIGNATURE]
            ?: throw IllegalStateException("No Companion pair-verify signature")
        if (credentials.peerIdentifier.isNotEmpty() && !credentials.peerIdentifier.contentEquals(peerIdentifier)) {
            throw IllegalStateException("Companion pair-verify identifier mismatch")
        }
        val peerInfo = serverPublicKey + peerIdentifier + x25519.publicKey
        if (!CryptoHelper.ed25519Verify(credentials.peerPublicKey, peerInfo, peerSignature)) {
            throw IllegalStateException("Companion pair-verify signature failed")
        }

        val deviceInfo = x25519.publicKey + credentials.clientId.toByteArray() + serverPublicKey
        val signature = CryptoHelper.ed25519Sign(credentials.clientPrivateKey, deviceInfo)
        val innerTlv = TlvEncoder()
            .add(TlvType.IDENTIFIER, credentials.clientId.toByteArray())
            .add(TlvType.SIGNATURE, signature)
            .encode()
        val m3Nonce = ByteArray(12)
        "PV-Msg03".toByteArray().copyInto(m3Nonce, 4)
        val encryptedInner = CryptoHelper.chaCha20Poly1305Encrypt(sessionKey, m3Nonce, innerTlv)

        response = exchangeAuth(
            CompanionFrameType.PV_NEXT,
            CompanionFrameType.PV_NEXT,
            linkedMapOf(
                PAIRING_DATA_KEY to TlvEncoder()
                    .add(TlvType.STATE, 3)
                    .add(TlvType.ENCRYPTED_DATA, encryptedInner)
                    .encode()
            )
        )
        responseTlv = pairingTlv(response)
        val state = responseTlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != null && state != 4) {
            throw IllegalStateException("Companion pair-verify expected M4, got state=$state")
        }

        val outputKey = CryptoHelper.hkdfSha512(sharedSecret, SRP_SALT, SRP_OUTPUT_INFO, 32)
        val inputKey = CryptoHelper.hkdfSha512(sharedSecret, SRP_SALT, SRP_INPUT_INFO, 32)
        connection.enableEncryption(outputKey, inputKey)
    }

    suspend fun startRemoteSession(credentials: PairingCredentials, deviceId: String) {
        sendRequest(
            "_systemInfo",
            linkedMapOf(
                "_bf" to 0,
                "_cf" to 512,
                "_clFl" to 128,
                "_i" to deviceId.replace("-", "").lowercase(),
                "_idsID" to credentials.clientId.toByteArray(),
                "_pubID" to deviceId,
                "_sf" to 256,
                "_sv" to "170.18",
                "model" to "Android",
                "name" to "Android Remote"
            )
        )
        sendRequest("_touchStart", linkedMapOf("_height" to 1000.0, "_tFl" to 0, "_width" to 1000.0))
        val localSid = System.currentTimeMillis() and 0x7FFFFFFFL
        val sessionResponse = sendRequest(
            "_sessionStart",
            linkedMapOf("_srvT" to "com.apple.tvremoteservices", "_sid" to localSid)
        )
        val content = sessionResponse["_c"] as? Map<*, *>
        val remoteSid = (content?.get("_sid") as? Number)?.toLong() ?: 0L
        remoteSessionId = (remoteSid shl 32) or (localSid.toLong() and 0xFFFFFFFFL)
        try {
            sendRequest("TVRCSessionStart", linkedMapOf("ProtocolVersionKey" to "1.2"))
        } catch (_: Exception) {
        }
        try {
            sendEvent("_interest", linkedMapOf("_regEvents" to listOf("_iMC")))
        } catch (_: Exception) {
        }
    }

    suspend fun pressButton(button: RemoteButton) {
        if (button == RemoteButton.VOLUME_UP || button == RemoteButton.VOLUME_DOWN) {
            pressVolumeButton(button)
            return
        }

        val command = button.companionCommand ?: return
        pressHidCommand(command)
    }

    private suspend fun pressVolumeButton(button: RemoteButton) {
        val command = button.companionCommand ?: return
        pressHidCommand(command)
        tryMediaControlVolumeStep(button)
    }

    private suspend fun pressHidCommand(command: Int) {
        sendRequest("_hidC", linkedMapOf("_hBtS" to 1, "_hidC" to command))
        delay(30)
        sendRequest("_hidC", linkedMapOf("_hBtS" to 2, "_hidC" to command))
    }

    private suspend fun tryMediaControlVolumeStep(button: RemoteButton) {
        try {
            val currentVolume = getMediaControlVolume() ?: return
            val direction = if (button == RemoteButton.VOLUME_UP) 1 else -1
            val nextVolume = (currentVolume + direction * VOLUME_STEP).coerceIn(0.0, 1.0)
            sendMediaControl(MEDIA_CONTROL_SET_VOLUME, linkedMapOf("_vol" to nextVolume))
        } catch (_: Exception) {
        }
    }

    private suspend fun getMediaControlVolume(): Double? {
        val response = sendMediaControl(MEDIA_CONTROL_GET_VOLUME)
        val content = response["_c"] as? Map<*, *> ?: return null
        return (content["_vol"] as? Number)?.toDouble()
    }

    private suspend fun sendMediaControl(
        command: Int,
        args: Map<String, Any?> = emptyMap()
    ): Map<String, Any?> {
        return sendRequest("_mcc", linkedMapOf("_mcc" to command, *args.toList().toTypedArray()))
    }

    private suspend fun exchangeAuth(
        sendType: CompanionFrameType,
        responseType: CompanionFrameType,
        data: Map<String, Any?>
    ): Map<String, Any?> {
        sendOpack(sendType, data)
        while (true) {
            val frame = connection.receive()
            if (frame.type != responseType) continue
            return unpackMap(frame.payload)
        }
    }

    private suspend fun sendRequest(identifier: String, content: Map<String, Any?>): Map<String, Any?> {
        val requestXid = xid++
        sendOpack(
            CompanionFrameType.E_OPACK,
            linkedMapOf(
                "_i" to identifier,
                "_t" to 2,
                "_c" to content,
                "_x" to requestXid
            )
        )
        while (true) {
            val frame = connection.receive()
            if (frame.type != CompanionFrameType.E_OPACK) continue
            val response = unpackMap(frame.payload)
            val responseXid = (response["_x"] as? Number)?.toInt()
            if (responseXid == requestXid) {
                response["_em"]?.let { throw IllegalStateException(it.toString()) }
                return response
            }
        }
    }

    private suspend fun sendEvent(identifier: String, content: Map<String, Any?>) {
        sendOpack(
            CompanionFrameType.E_OPACK,
            linkedMapOf(
                "_i" to identifier,
                "_t" to 1,
                "_c" to content,
                "_x" to xid++
            )
        )
    }

    private suspend fun sendOpack(type: CompanionFrameType, data: Map<String, Any?>) {
        val payload = Opack.pack(data)
        connection.send(type, payload)
    }

    @Suppress("UNCHECKED_CAST")
    private fun unpackMap(payload: ByteArray): Map<String, Any?> {
        return Opack.unpack(payload) as? Map<String, Any?>
            ?: throw IllegalStateException("Expected OPACK dictionary")
    }

    private fun pairingTlv(message: Map<String, Any?>): Map<Int, ByteArray> {
        val pairingData = message[PAIRING_DATA_KEY] as? ByteArray
            ?: throw IllegalStateException("No Companion pairing data")
        val tlv = TlvDecoder(pairingData).decode()
        tlv[TlvType.ERROR]?.firstOrNull()?.let { error ->
            throw IllegalStateException("Companion pairing error $error (${pairingErrorMessage(error.toInt())})")
        }
        return tlv
    }

    private fun pairingErrorMessage(error: Int): String {
        return when (error) {
            1 -> "unknown"
            2 -> "authentication failed or PIN rejected"
            3 -> "pairing backoff"
            4 -> "too many paired remotes"
            5 -> "too many PIN attempts"
            6 -> "pairing unavailable"
            7 -> "device busy"
            else -> "unknown"
        }
    }
}
