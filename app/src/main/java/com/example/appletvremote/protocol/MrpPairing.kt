package com.example.appletvremote.protocol

import android.util.Log
import com.example.appletvremote.model.PairingCredentials
import java.util.UUID

/**
 * Implements MRP Pair-Setup and Pair-Verify protocols for Apple TV.
 *
 * Connection sequence:
 *   1. TLS connect
 *   2. Send DeviceInfoMessage (required before anything else)
 *   3. Receive Apple TV's DeviceInfoMessage
 *   4. Start Pair-Setup or Pair-Verify
 */
class MrpPairing(private val connection: MrpConnection) {

    companion object {
        private const val TAG = "MrpPairing"
        private const val PAIR_SETUP_IDENTITY = "Pair-Setup"
        // CryptoPairingMessage is field 39 in ProtocolMessage
        private const val CRYPTO_PAIRING_FIELD = 39
    }

    private val srp = SrpClient()
    private var clientId = UUID.randomUUID().toString()
    private var edKeyPair: CryptoHelper.Ed25519KeyPair? = null

    /**
     * Send DeviceInfo and wait for the Apple TV's response.
     * Must be called before pairing or pair-verify.
     */
    suspend fun sendDeviceInfo() {
        Log.d(TAG, "Sending DeviceInfoMessage")
        val msg = ProtobufHelper.buildDeviceInfoMessage(clientId, "Android Remote")
        connection.sendMessage(msg)

        // Read the Apple TV's DeviceInfoMessage response
        Log.d(TAG, "Waiting for Apple TV DeviceInfoMessage...")
        val response = connection.receiveMessage()
        val parsed = ProtobufHelper.parseMessage(response)
        val msgType = parsed[1] as? Long
        Log.d(TAG, "Received message type: $msgType")

        // Apple TV may send multiple messages — consume until we get past DeviceInfo
        // or just proceed since we only need to know it responded
        if (msgType == ProtobufHelper.MSG_TYPE_DEVICE_INFO.toLong()) {
            val innerBytes = parsed[17] as? ByteArray
            if (innerBytes != null) {
                val inner = ProtobufHelper.parseMessage(innerBytes)
                val deviceName = (inner[2] as? ByteArray)?.let { String(it) } ?: "unknown"
                Log.d(TAG, "Apple TV identified as: $deviceName")
            }
        }
    }

    /**
     * Extract pairing data from a ProtocolMessage containing CryptoPairingMessage (field 39).
     */
    private fun extractPairingData(response: ByteArray): ByteArray {
        val outer = ProtobufHelper.parseMessage(response)
        val msgType = outer[1] as? Long
        Log.d(TAG, "Response message type: $msgType")

        // CryptoPairingMessage is in field 39
        val innerBytes = outer[CRYPTO_PAIRING_FIELD] as? ByteArray
            ?: throw IllegalStateException("No CryptoPairingMessage (field $CRYPTO_PAIRING_FIELD) in response, got fields: ${outer.keys}")
        val inner = ProtobufHelper.parseMessage(innerBytes)
        return inner[1] as? ByteArray
            ?: throw IllegalStateException("No pairingData in CryptoPairingMessage")
    }

    suspend fun pairSetupM1() {
        Log.d(TAG, "Pair-Setup M1: Sending start request")
        val tlv = TlvEncoder()
            .add(TlvType.STATE, 1)
            .add(TlvType.METHOD, 0)
            .encode()

        val msg = ProtobufHelper.buildCryptoPairingMessage(tlv)
        connection.sendMessage(msg)
    }

    suspend fun pairSetupM2(): Pair<ByteArray, ByteArray> {
        Log.d(TAG, "Pair-Setup M2: Waiting for server challenge")

        // Apple TV may send other messages before the pairing response — skip them
        var pairingData: ByteArray? = null
        for (i in 0 until 5) {
            val response = connection.receiveMessage()
            val outer = ProtobufHelper.parseMessage(response)
            val msgType = outer[1] as? Long
            Log.d(TAG, "M2 received message type: $msgType, fields: ${outer.keys}")

            if (outer.containsKey(CRYPTO_PAIRING_FIELD)) {
                val innerBytes = outer[CRYPTO_PAIRING_FIELD] as ByteArray
                val inner = ProtobufHelper.parseMessage(innerBytes)
                pairingData = inner[1] as? ByteArray
                break
            }
            Log.d(TAG, "Skipping non-pairing message type $msgType")
        }

        if (pairingData == null) {
            throw IllegalStateException("Never received CryptoPairingMessage response")
        }

        val tlv = TlvDecoder(pairingData).decode()
        val state = tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != 2) {
            val error = tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Expected M2 (state 2), got state=$state, error=$error")
        }

        val salt = tlv[TlvType.SALT] ?: throw IllegalStateException("No salt in M2")
        val serverPubKey = tlv[TlvType.PUBLIC_KEY] ?: throw IllegalStateException("No public key in M2")
        Log.d(TAG, "Pair-Setup M2: Received salt (${salt.size}B) and server public key (${serverPubKey.size}B)")
        return salt to serverPubKey
    }

    suspend fun pairSetupM3(pin: String, salt: ByteArray, serverPublicKey: ByteArray) {
        Log.d(TAG, "Pair-Setup M3: Computing SRP proof with PIN")
        srp.generateCredentials()
        val proof = srp.processChallenge(PAIR_SETUP_IDENTITY, pin, salt, serverPublicKey)

        val tlv = TlvEncoder()
            .add(TlvType.STATE, 3)
            .add(TlvType.PUBLIC_KEY, srp.publicKey)
            .add(TlvType.PROOF, proof)
            .encode()

        val msg = ProtobufHelper.buildCryptoPairingMessage(tlv)
        connection.sendMessage(msg)
    }

    suspend fun pairSetupM4() {
        Log.d(TAG, "Pair-Setup M4: Verifying server proof")
        val response = connection.receiveMessage()
        val pairingData = extractPairingData(response)

        val tlv = TlvDecoder(pairingData).decode()
        val state = tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != 4) {
            val error = tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Expected M4 (state 4), got state=$state, error=$error")
        }

        val serverProof = tlv[TlvType.PROOF] ?: throw IllegalStateException("No server proof in M4")
        if (!srp.verifyServerProof(serverProof)) {
            throw IllegalStateException("Server proof verification failed")
        }
        Log.d(TAG, "Pair-Setup M4: Server proof verified")
    }

    suspend fun pairSetupM5() {
        Log.d(TAG, "Pair-Setup M5: Sending encrypted credentials")
        val sessionKey = srp.getSessionKey()

        val encryptKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", 32
        )

        edKeyPair = CryptoHelper.generateEd25519KeyPair()
        val ed = edKeyPair!!

        val signingKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", 32
        )

        val idBytes = clientId.toByteArray()
        val messageToSign = signingKey + idBytes + ed.publicKey
        val signature = CryptoHelper.ed25519Sign(ed.privateKey, messageToSign)

        val innerTlv = TlvEncoder()
            .add(TlvType.IDENTIFIER, idBytes)
            .add(TlvType.PUBLIC_KEY, ed.publicKey)
            .add(TlvType.SIGNATURE, signature)
            .encode()

        val nonce = ByteArray(12)
        "PS-Msg05".toByteArray().copyInto(nonce, 4)
        val encryptedData = CryptoHelper.chaCha20Poly1305Encrypt(encryptKey, nonce, innerTlv)

        val tlv = TlvEncoder()
            .add(TlvType.STATE, 5)
            .add(TlvType.ENCRYPTED_DATA, encryptedData)
            .encode()

        val msg = ProtobufHelper.buildCryptoPairingMessage(tlv)
        connection.sendMessage(msg)
    }

    suspend fun pairSetupM6(): PairingCredentials {
        Log.d(TAG, "Pair-Setup M6: Receiving server credentials")
        val response = connection.receiveMessage()
        val pairingData = extractPairingData(response)

        val tlv = TlvDecoder(pairingData).decode()
        val state = tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != 6) {
            val error = tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Expected M6 (state 6), got state=$state, error=$error")
        }

        val encryptedData = tlv[TlvType.ENCRYPTED_DATA] ?: throw IllegalStateException("No encrypted data in M6")

        val sessionKey = srp.getSessionKey()
        val encryptKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", 32
        )
        val nonce = ByteArray(12)
        "PS-Msg06".toByteArray().copyInto(nonce, 4)
        val decrypted = CryptoHelper.chaCha20Poly1305Decrypt(encryptKey, nonce, encryptedData)

        val serverTlv = TlvDecoder(decrypted).decode()
        val peerPublicKey = serverTlv[TlvType.PUBLIC_KEY] ?: throw IllegalStateException("No server public key in M6")

        Log.d(TAG, "Pair-Setup complete!")
        val ed = edKeyPair!!
        return PairingCredentials(
            deviceId = "",
            clientId = clientId,
            clientPrivateKey = ed.privateKey,
            clientPublicKey = ed.publicKey,
            peerPublicKey = peerPublicKey
        )
    }

    suspend fun pairVerify(credentials: PairingCredentials): MrpCipher {
        Log.d(TAG, "Pair-Verify M1: Sending X25519 public key")

        val x25519 = CryptoHelper.generateX25519KeyPair()

        val m1Tlv = TlvEncoder()
            .add(TlvType.STATE, 1)
            .add(TlvType.PUBLIC_KEY, x25519.publicKey)
            .encode()
        connection.sendMessage(ProtobufHelper.buildCryptoPairingMessage(m1Tlv))

        // M2
        Log.d(TAG, "Pair-Verify M2: Receiving server response")
        val m2Response = connection.receiveMessage()
        val m2PairingData = extractPairingData(m2Response)

        val m2Tlv = TlvDecoder(m2PairingData).decode()
        val m2State = m2Tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (m2State != 2) {
            val error = m2Tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Pair-Verify M2 failed: state=$m2State, error=$error")
        }

        val serverX25519PubKey = m2Tlv[TlvType.PUBLIC_KEY]
            ?: throw IllegalStateException("No server public key in M2")

        val sharedSecret = CryptoHelper.x25519SharedSecret(x25519.privateKey, serverX25519PubKey)

        val sessionKey = CryptoHelper.hkdfSha512(
            sharedSecret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", 32
        )

        // M3
        Log.d(TAG, "Pair-Verify M3: Sending encrypted proof")
        val deviceInfo = x25519.publicKey + credentials.clientId.toByteArray() + serverX25519PubKey
        val signature = CryptoHelper.ed25519Sign(credentials.clientPrivateKey, deviceInfo)

        val innerTlv = TlvEncoder()
            .add(TlvType.IDENTIFIER, credentials.clientId.toByteArray())
            .add(TlvType.SIGNATURE, signature)
            .encode()

        val nonce = ByteArray(12)
        "PV-Msg03".toByteArray().copyInto(nonce, 4)
        val encryptedInner = CryptoHelper.chaCha20Poly1305Encrypt(sessionKey, nonce, innerTlv)

        val m3Tlv = TlvEncoder()
            .add(TlvType.STATE, 3)
            .add(TlvType.ENCRYPTED_DATA, encryptedInner)
            .encode()
        connection.sendMessage(ProtobufHelper.buildCryptoPairingMessage(m3Tlv))

        // M4
        Log.d(TAG, "Pair-Verify M4: Waiting for confirmation")
        val m4Response = connection.receiveMessage()
        val m4PairingData = extractPairingData(m4Response)
        val m4Tlv = TlvDecoder(m4PairingData).decode()
        val m4State = m4Tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (m4State != 4) {
            val error = m4Tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Pair-Verify M4 failed: state=$m4State, error=$error")
        }

        val readKey = CryptoHelper.hkdfSha512(
            sharedSecret, "MediaRemote-Salt", "MediaRemote-Read-Encryption-Key", 32
        )
        val writeKey = CryptoHelper.hkdfSha512(
            sharedSecret, "MediaRemote-Salt", "MediaRemote-Write-Encryption-Key", 32
        )

        Log.d(TAG, "Pair-Verify complete! Encryption established.")
        return MrpCipher(readKey, writeKey)
    }
}
