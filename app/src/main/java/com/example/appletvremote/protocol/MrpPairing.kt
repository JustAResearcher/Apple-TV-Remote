package com.example.appletvremote.protocol

import android.util.Log
import com.example.appletvremote.model.PairingCredentials
import java.util.UUID

/**
 * Implements MRP Pair-Setup and Pair-Verify protocols for Apple TV.
 *
 * Pair-Setup (initial pairing, requires PIN from Apple TV screen):
 *   M1: Client sends State=1, Method=0
 *   M2: Server sends State=2, Salt, PublicKey (and shows PIN on screen)
 *   M3: Client sends State=3, PublicKey(A), Proof(M1) - computed with PIN
 *   M4: Server sends State=4, Proof(M2)
 *   M5: Client sends State=5, EncryptedData (Ed25519 pubkey + signature)
 *   M6: Server sends State=6, EncryptedData (server Ed25519 pubkey + signature)
 *
 * Pair-Verify (reconnection using stored credentials):
 *   M1: Client sends State=1, PublicKey (X25519)
 *   M2: Server sends State=2, PublicKey, EncryptedData
 *   M3: Client sends State=3, EncryptedData
 *   M4: Server sends State=4
 */
class MrpPairing(private val connection: MrpConnection) {

    companion object {
        private const val TAG = "MrpPairing"
        private const val PAIR_SETUP_IDENTITY = "Pair-Setup"
    }

    private val srp = SrpClient()
    private var clientId = UUID.randomUUID().toString()
    private var edKeyPair: CryptoHelper.Ed25519KeyPair? = null

    /**
     * Initiate Pair-Setup M1.
     * Call this to start pairing. The Apple TV will display a PIN.
     */
    suspend fun pairSetupM1() {
        Log.d(TAG, "Pair-Setup M1: Sending start request")
        val tlv = TlvEncoder()
            .add(TlvType.STATE, 1)
            .add(TlvType.METHOD, 0)
            .encode()

        val msg = ProtobufHelper.buildCryptoPairingMessage(tlv)
        connection.sendMessage(msg)
    }

    /**
     * Receive and parse Pair-Setup M2.
     * Returns the salt and server public key.
     */
    suspend fun pairSetupM2(): Pair<ByteArray, ByteArray> {
        Log.d(TAG, "Pair-Setup M2: Waiting for server challenge")
        val response = connection.receiveMessage()
        val outer = ProtobufHelper.parseMessage(response)
        val innerBytes = outer[46] as? ByteArray ?: throw IllegalStateException("No CryptoPairingMessage in response")
        val inner = ProtobufHelper.parseMessage(innerBytes)
        val pairingData = inner[1] as? ByteArray ?: throw IllegalStateException("No pairing data")

        val tlv = TlvDecoder(pairingData).decode()
        val state = tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != 2) {
            val error = tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Expected M2 (state 2), got state=$state, error=$error")
        }

        val salt = tlv[TlvType.SALT] ?: throw IllegalStateException("No salt in M2")
        val serverPubKey = tlv[TlvType.PUBLIC_KEY] ?: throw IllegalStateException("No public key in M2")
        Log.d(TAG, "Pair-Setup M2: Received salt (${salt.size} bytes) and server public key (${serverPubKey.size} bytes)")
        return salt to serverPubKey
    }

    /**
     * Send Pair-Setup M3 with the PIN entered by the user.
     */
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

    /**
     * Receive and verify Pair-Setup M4.
     */
    suspend fun pairSetupM4() {
        Log.d(TAG, "Pair-Setup M4: Verifying server proof")
        val response = connection.receiveMessage()
        val outer = ProtobufHelper.parseMessage(response)
        val innerBytes = outer[46] as? ByteArray ?: throw IllegalStateException("No CryptoPairingMessage")
        val inner = ProtobufHelper.parseMessage(innerBytes)
        val pairingData = inner[1] as? ByteArray ?: throw IllegalStateException("No pairing data")

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

    /**
     * Send Pair-Setup M5 with encrypted Ed25519 credentials.
     */
    suspend fun pairSetupM5() {
        Log.d(TAG, "Pair-Setup M5: Sending encrypted credentials")
        val sessionKey = srp.getSessionKey()

        // Derive encryption key for M5
        val encryptKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", 32
        )

        // Generate Ed25519 keypair for long-term identity
        edKeyPair = CryptoHelper.generateEd25519KeyPair()
        val ed = edKeyPair!!

        // Derive signing key
        val signingKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", 32
        )

        // Build message to sign: signingKey + clientId + ed25519PublicKey
        val idBytes = clientId.toByteArray()
        val messageToSign = signingKey + idBytes + ed.publicKey

        // Sign with Ed25519
        val signature = CryptoHelper.ed25519Sign(ed.privateKey, messageToSign)

        // Build inner TLV: identifier + public key + signature
        val innerTlv = TlvEncoder()
            .add(TlvType.IDENTIFIER, idBytes)
            .add(TlvType.PUBLIC_KEY, ed.publicKey)
            .add(TlvType.SIGNATURE, signature)
            .encode()

        // Encrypt with ChaCha20-Poly1305
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

    /**
     * Receive Pair-Setup M6. Returns the PairingCredentials for storage.
     */
    suspend fun pairSetupM6(): PairingCredentials {
        Log.d(TAG, "Pair-Setup M6: Receiving server credentials")
        val response = connection.receiveMessage()
        val outer = ProtobufHelper.parseMessage(response)
        val innerBytes = outer[46] as? ByteArray ?: throw IllegalStateException("No CryptoPairingMessage")
        val inner = ProtobufHelper.parseMessage(innerBytes)
        val pairingData = inner[1] as? ByteArray ?: throw IllegalStateException("No pairing data")

        val tlv = TlvDecoder(pairingData).decode()
        val state = tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (state != 6) {
            val error = tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Expected M6 (state 6), got state=$state, error=$error")
        }

        val encryptedData = tlv[TlvType.ENCRYPTED_DATA] ?: throw IllegalStateException("No encrypted data in M6")

        // Decrypt server's credentials
        val sessionKey = srp.getSessionKey()
        val encryptKey = CryptoHelper.hkdfSha512(
            sessionKey, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", 32
        )
        val nonce = ByteArray(12)
        "PS-Msg06".toByteArray().copyInto(nonce, 4)
        val decrypted = CryptoHelper.chaCha20Poly1305Decrypt(encryptKey, nonce, encryptedData)

        val serverTlv = TlvDecoder(decrypted).decode()
        val peerPublicKey = serverTlv[TlvType.PUBLIC_KEY] ?: throw IllegalStateException("No server public key in M6")

        Log.d(TAG, "Pair-Setup complete! Credentials stored.")
        val ed = edKeyPair!!
        return PairingCredentials(
            deviceId = "", // will be set by caller
            clientId = clientId,
            clientPrivateKey = ed.privateKey,
            clientPublicKey = ed.publicKey,
            peerPublicKey = peerPublicKey
        )
    }

    /**
     * Perform Pair-Verify using stored credentials.
     * This establishes an encrypted session for sending remote commands.
     * Returns the MrpCipher for encrypting subsequent messages.
     */
    suspend fun pairVerify(credentials: PairingCredentials): MrpCipher {
        Log.d(TAG, "Pair-Verify M1: Sending X25519 public key")

        // Generate ephemeral X25519 keypair
        val x25519 = CryptoHelper.generateX25519KeyPair()

        // M1: Send our X25519 public key
        val m1Tlv = TlvEncoder()
            .add(TlvType.STATE, 1)
            .add(TlvType.PUBLIC_KEY, x25519.publicKey)
            .encode()
        val m1Msg = ProtobufHelper.buildCryptoPairingMessage(m1Tlv)
        connection.sendMessage(m1Msg)

        // M2: Receive server's X25519 public key + encrypted data
        Log.d(TAG, "Pair-Verify M2: Receiving server response")
        val m2Response = connection.receiveMessage()
        val m2Outer = ProtobufHelper.parseMessage(m2Response)
        val m2InnerBytes = m2Outer[46] as? ByteArray ?: throw IllegalStateException("No CryptoPairingMessage in M2")
        val m2Inner = ProtobufHelper.parseMessage(m2InnerBytes)
        val m2PairingData = m2Inner[1] as? ByteArray ?: throw IllegalStateException("No pairing data in M2")

        val m2Tlv = TlvDecoder(m2PairingData).decode()
        val m2State = m2Tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (m2State != 2) {
            val error = m2Tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Pair-Verify M2 failed: state=$m2State, error=$error")
        }

        val serverX25519PubKey = m2Tlv[TlvType.PUBLIC_KEY]
            ?: throw IllegalStateException("No server public key in M2")

        // Compute shared secret
        val sharedSecret = CryptoHelper.x25519SharedSecret(x25519.privateKey, serverX25519PubKey)

        // Derive session encryption key for verify messages
        val sessionKey = CryptoHelper.hkdfSha512(
            sharedSecret, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", 32
        )

        // M3: Send encrypted proof
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
        val m3Msg = ProtobufHelper.buildCryptoPairingMessage(m3Tlv)
        connection.sendMessage(m3Msg)

        // M4: Receive confirmation
        Log.d(TAG, "Pair-Verify M4: Waiting for confirmation")
        val m4Response = connection.receiveMessage()
        val m4Outer = ProtobufHelper.parseMessage(m4Response)
        val m4InnerBytes = m4Outer[46] as? ByteArray ?: throw IllegalStateException("No CryptoPairingMessage in M4")
        val m4Inner = ProtobufHelper.parseMessage(m4InnerBytes)
        val m4PairingData = m4Inner[1] as? ByteArray ?: throw IllegalStateException("No pairing data in M4")
        val m4Tlv = TlvDecoder(m4PairingData).decode()
        val m4State = m4Tlv[TlvType.STATE]?.firstOrNull()?.toInt()
        if (m4State != 4) {
            val error = m4Tlv[TlvType.ERROR]?.firstOrNull()?.toInt()
            throw IllegalStateException("Pair-Verify M4 failed: state=$m4State, error=$error")
        }

        // Derive read/write encryption keys for the session
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
