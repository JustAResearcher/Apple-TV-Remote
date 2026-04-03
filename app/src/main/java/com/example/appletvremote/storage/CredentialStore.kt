package com.example.appletvremote.storage

import android.content.Context
import android.util.Base64
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.appletvremote.model.PairingCredentials
import kotlinx.coroutines.flow.first
import org.json.JSONObject

private val Context.dataStore by preferencesDataStore(name = "apple_tv_credentials")

/**
 * Persists pairing credentials so the app can reconnect without re-pairing.
 * Each Apple TV device has its own stored credential set keyed by device ID.
 */
class CredentialStore(private val context: Context) {

    companion object {
        private fun keyFor(deviceId: String) = stringPreferencesKey("cred_$deviceId")
    }

    suspend fun save(credentials: PairingCredentials) {
        val json = JSONObject().apply {
            put("deviceId", credentials.deviceId)
            put("clientId", credentials.clientId)
            put("clientPrivateKey", Base64.encodeToString(credentials.clientPrivateKey, Base64.NO_WRAP))
            put("clientPublicKey", Base64.encodeToString(credentials.clientPublicKey, Base64.NO_WRAP))
            put("peerPublicKey", Base64.encodeToString(credentials.peerPublicKey, Base64.NO_WRAP))
        }
        context.dataStore.edit { prefs ->
            prefs[keyFor(credentials.deviceId)] = json.toString()
        }
    }

    suspend fun load(deviceId: String): PairingCredentials? {
        val prefs = context.dataStore.data.first()
        val jsonStr = prefs[keyFor(deviceId)] ?: return null
        return try {
            val json = JSONObject(jsonStr)
            PairingCredentials(
                deviceId = json.getString("deviceId"),
                clientId = json.getString("clientId"),
                clientPrivateKey = Base64.decode(json.getString("clientPrivateKey"), Base64.NO_WRAP),
                clientPublicKey = Base64.decode(json.getString("clientPublicKey"), Base64.NO_WRAP),
                peerPublicKey = Base64.decode(json.getString("peerPublicKey"), Base64.NO_WRAP)
            )
        } catch (_: Exception) {
            null
        }
    }

    suspend fun delete(deviceId: String) {
        context.dataStore.edit { prefs ->
            prefs.remove(keyFor(deviceId))
        }
    }

    suspend fun hasCreds(deviceId: String): Boolean = load(deviceId) != null
}
