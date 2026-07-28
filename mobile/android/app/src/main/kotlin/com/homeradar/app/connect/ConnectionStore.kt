package com.homeradar.app.connect

import android.content.Context
import android.content.SharedPreferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.homeradar.core.net.TokenProvider
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.connectionDataStore by preferencesDataStore(name = "homeradar_connection")
private val ADDRESS_KEY = stringPreferencesKey("appliance_address")

private const val ENCRYPTED_PREFS_FILE_NAME = "homeradar_secure_prefs"
private const val TOKEN_KEY = "pairing_token"

/**
 * Owns the two pieces of persisted pairing state:
 *  - the plain appliance address ("homeradar.local:8000"), in DataStore Preferences
 *  - the secret pairing token, in an EncryptedSharedPreferences file
 *
 * Implements `:core`'s [TokenProvider] directly. EncryptedSharedPreferences
 * reads are synchronous, so [currentToken] satisfies the interface's
 * synchronous signature with no adapter/wrapper class needed -- an instance
 * of this class can be handed straight into `HomeRadarClient`/`DashboardSocket`.
 */
class ConnectionStore(context: Context) : TokenProvider {

    private val appContext = context.applicationContext

    private val securePrefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            appContext,
            ENCRYPTED_PREFS_FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    override fun currentToken(): String? = securePrefs.getString(TOKEN_KEY, null)

    fun saveToken(token: String) {
        securePrefs.edit().putString(TOKEN_KEY, token).apply()
    }

    fun clearToken() {
        securePrefs.edit().remove(TOKEN_KEY).apply()
    }

    /** Emits the saved address (or null if never set) every time it changes. */
    val addressFlow: Flow<String?> =
        appContext.connectionDataStore.data.map { prefs -> prefs[ADDRESS_KEY] }

    suspend fun saveAddress(address: String) {
        appContext.connectionDataStore.edit { prefs -> prefs[ADDRESS_KEY] = address }
    }

    suspend fun clearAddress() {
        appContext.connectionDataStore.edit { prefs -> prefs.remove(ADDRESS_KEY) }
    }
}

/**
 * Prefixes a bare "host:port" with `http://` if the user didn't type a
 * scheme. The appliance is reached over plain HTTP on the local network, and
 * this same string is used verbatim as `baseUrl` for both `HomeRadarClient`
 * (REST) and `DashboardSocket` (which upgrades an http(s) request to a
 * websocket -- OkHttp requires an http/https scheme URL for `newWebSocket`,
 * not a literal `ws://`).
 */
fun normalizeApplianceAddress(address: String): String {
    val trimmed = address.trim()
    return if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
        trimmed
    } else {
        "http://$trimmed"
    }
}
