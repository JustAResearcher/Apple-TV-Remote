package com.example.appletvremote.protocol

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * SRP-6a client implementation compatible with Apple TV pairing.
 * Uses the 3072-bit group from RFC 5054 with SHA-512.
 */
class SrpClient {

    companion object {
        // 3072-bit safe prime from RFC 5054
        val N = BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
            "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
            "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
            16
        )
        val g = BigInteger.valueOf(5)

        private val nLength = (N.bitLength() + 7) / 8
    }

    private val random = SecureRandom()
    private var privateKey: BigInteger = BigInteger.ZERO // a
    lateinit var publicKey: ByteArray  // A
    private lateinit var sessionKey: ByteArray // K

    private lateinit var clientProof: ByteArray // M1

    fun generateCredentials(): ByteArray {
        // Generate random private key a
        privateKey = BigInteger(256, random)

        // A = g^a mod N
        val A = g.modPow(privateKey, N)
        publicKey = padToN(A.toByteArray().stripLeadingZeros())
        return publicKey
    }

    fun processChallenge(
        identity: String,
        password: String,
        salt: ByteArray,
        serverPublicKey: ByteArray
    ): ByteArray {
        val B = BigInteger(1, serverPublicKey)

        // Check B % N != 0
        if (B.mod(N) == BigInteger.ZERO) {
            throw IllegalStateException("Invalid server public key")
        }

        val A = BigInteger(1, publicKey)

        // k = H(N | PAD(g))
        val k = hashBigInteger(N.toByteArray().stripLeadingZeros(), padToN(g.toByteArray().stripLeadingZeros()))

        // u = H(PAD(A) | PAD(B))
        val u = hashBigInteger(padToN(publicKey), padToN(serverPublicKey))
        if (u == BigInteger.ZERO) {
            throw IllegalStateException("Invalid u value")
        }

        // x = H(salt | H(identity | ":" | password))
        val innerHash = sha512("$identity:$password".toByteArray())
        val x = hashBigInteger(salt, innerHash)

        // S = (B - k * g^x) ^ (a + u * x) mod N
        val gx = g.modPow(x, N)
        val kgx = k.multiply(gx).mod(N)
        val diff = B.subtract(kgx).mod(N)
        val exp = privateKey.add(u.multiply(x)).mod(N.subtract(BigInteger.ONE))
        val S = diff.modPow(exp, N)

        // K = H(S)
        sessionKey = sha512(padToN(S.toByteArray().stripLeadingZeros()))

        // M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)
        val hN = sha512(N.toByteArray().stripLeadingZeros())
        val hg = sha512(padToN(g.toByteArray().stripLeadingZeros()))
        val hNxorHg = ByteArray(hN.size) { (hN[it].toInt() xor hg[it].toInt()).toByte() }
        val hI = sha512(identity.toByteArray())

        clientProof = sha512(
            hNxorHg,
            hI,
            salt,
            padToN(publicKey),
            padToN(serverPublicKey),
            sessionKey
        )

        return clientProof
    }

    fun verifyServerProof(serverProof: ByteArray): Boolean {
        // M2 = H(A | M1 | K)
        val expectedM2 = sha512(padToN(publicKey), clientProof, sessionKey)
        return expectedM2.contentEquals(serverProof)
    }

    fun getSessionKey(): ByteArray = sessionKey

    private fun sha512(vararg data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-512")
        for (d in data) {
            digest.update(d)
        }
        return digest.digest()
    }

    private fun hashBigInteger(vararg data: ByteArray): BigInteger {
        return BigInteger(1, sha512(*data))
    }

    private fun padToN(data: ByteArray): ByteArray {
        if (data.size >= nLength) return data
        val padded = ByteArray(nLength)
        System.arraycopy(data, 0, padded, nLength - data.size, data.size)
        return padded
    }

    private fun ByteArray.stripLeadingZeros(): ByteArray {
        val firstNonZero = indexOfFirst { it != 0.toByte() }
        if (firstNonZero < 0) return byteArrayOf(0)
        return copyOfRange(firstNonZero, size)
    }
}
