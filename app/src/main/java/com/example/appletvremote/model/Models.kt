package com.example.appletvremote.model

data class AppleTVDevice(
    val name: String,
    val host: String,
    val port: Int,
    val uniqueId: String,
    val protocol: AppleTVProtocol = AppleTVProtocol.MRP
)

data class PairingCredentials(
    val deviceId: String,
    val clientId: String,
    val clientPrivateKey: ByteArray,
    val clientPublicKey: ByteArray,
    val peerPublicKey: ByteArray,
    val peerIdentifier: ByteArray = ByteArray(0)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingCredentials) return false
        return deviceId == other.deviceId && clientId == other.clientId
    }

    override fun hashCode(): Int = deviceId.hashCode() * 31 + clientId.hashCode()
}

enum class AppleTVProtocol {
    MRP,
    COMPANION
}

enum class RemoteButton(val usagePage: Int, val usage: Int, val companionCommand: Int?) {
    UP(0x01, 0x8C, 1),
    DOWN(0x01, 0x8D, 2),
    LEFT(0x01, 0x8B, 3),
    RIGHT(0x01, 0x8A, 4),
    SELECT(0x01, 0x89, 6),
    MENU(0x01, 0x86, 5),
    HOME(0x0C, 0x40, 7),
    PLAY_PAUSE(0x0C, 0xCD, 14),
    VOLUME_UP(0x0C, 0xE9, 8),
    VOLUME_DOWN(0x0C, 0xEA, 9),
    NEXT(0x0C, 0xB5, null),
    PREVIOUS(0x0C, 0xB6, null),
    POWER(0x01, 0x82, 12)
}

enum class ConnectionState {
    DISCONNECTED,
    DISCOVERING,
    CONNECTING,
    PAIRING,
    PAIR_VERIFY,
    CONNECTED
}
