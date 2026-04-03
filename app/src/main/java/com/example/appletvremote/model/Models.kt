package com.example.appletvremote.model

data class AppleTVDevice(
    val name: String,
    val host: String,
    val port: Int,
    val uniqueId: String
)

data class PairingCredentials(
    val deviceId: String,
    val clientId: String,
    val clientPrivateKey: ByteArray,
    val clientPublicKey: ByteArray,
    val peerPublicKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingCredentials) return false
        return deviceId == other.deviceId && clientId == other.clientId
    }

    override fun hashCode(): Int = deviceId.hashCode() * 31 + clientId.hashCode()
}

enum class RemoteButton(val usagePage: Int, val usage: Int) {
    UP(0x01, 0x8C),
    DOWN(0x01, 0x8D),
    LEFT(0x01, 0x8E),
    RIGHT(0x01, 0x8F),
    SELECT(0x01, 0x89),
    MENU(0x01, 0x86),
    HOME(0x0C, 0x40),
    PLAY_PAUSE(0x0C, 0xCD),
    VOLUME_UP(0x0C, 0xE9),
    VOLUME_DOWN(0x0C, 0xEA),
    NEXT(0x0C, 0xB5),
    PREVIOUS(0x0C, 0xB6),
    POWER(0x0C, 0x30)
}

enum class ConnectionState {
    DISCONNECTED,
    DISCOVERING,
    CONNECTING,
    PAIRING,
    PAIR_VERIFY,
    CONNECTED
}
