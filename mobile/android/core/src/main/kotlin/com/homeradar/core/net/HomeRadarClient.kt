package com.homeradar.core.net

import com.homeradar.core.model.Alert
import com.homeradar.core.model.AlertResolveResult
import com.homeradar.core.model.Dashboard
import com.homeradar.core.model.Device
import com.homeradar.core.model.HomeRadarJson
import com.homeradar.core.model.PairClaimResult
import com.homeradar.core.model.Settings
import com.homeradar.core.model.Status
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

/**
 * Thin REST client for the HomeRadar appliance's FastAPI backend. Every
 * request is built through OkHttp and executed synchronously inside
 * `withContext(Dispatchers.IO)`, so callers get suspend functions without
 * this module needing a separate coroutines-okhttp dependency.
 */
class HomeRadarClient(
    private val baseUrl: String,
    private val tokenProvider: TokenProvider,
    private val httpClient: OkHttpClient = OkHttpClient(),
) {
    private fun url(path: String): String = baseUrl.trimEnd('/') + path

    /**
     * The single attach-point for auth on every outgoing request. Nothing in
     * this class should set the auth header any other way.
     */
    private fun Request.Builder.attachAuth(): Request.Builder {
        tokenProvider.currentToken()?.let { header(AUTH_HEADER_NAME, it) }
        return this
    }

    private suspend fun execute(request: Request): Response =
        withContext(Dispatchers.IO) { httpClient.newCall(request).execute() }

    private suspend fun executeForBody(request: Request): String {
        execute(request).use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw HomeRadarApiException(response.code, body)
            }
            return body
        }
    }

    suspend fun getStatus(): Status {
        val request = Request.Builder().url(url("/status")).attachAuth().build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun getDashboard(): Dashboard {
        val request = Request.Builder().url(url("/dashboard")).attachAuth().build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun getDevices(): List<Device> {
        val request = Request.Builder().url(url("/devices")).attachAuth().build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun patchDeviceAuthorization(id: Int, state: Int): Device {
        val payload = buildJsonObject { put("state", state) }
        val body = HomeRadarJson.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder()
            .url(url("/devices/$id/authorization"))
            .patch(body)
            .attachAuth()
            .build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun getAlerts(unresolvedOnly: Boolean = false): List<Alert> {
        val request = Request.Builder()
            .url(url("/alerts?unresolved_only=$unresolvedOnly"))
            .attachAuth()
            .build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun patchAlertResolved(id: Int, resolved: Boolean = true): AlertResolveResult {
        val payload = buildJsonObject { put("resolved", resolved) }
        val body = HomeRadarJson.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder()
            .url(url("/alerts/$id"))
            .patch(body)
            .attachAuth()
            .build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun getSettings(): Settings {
        val request = Request.Builder().url(url("/settings")).attachAuth().build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    /**
     * Partial update of appliance settings. Keys map 1:1 onto the backend's
     * `SettingsUpdate` Pydantic model field names; omit a key to leave that
     * field unchanged. Supported value types: String, Boolean, Int, Double,
     * Long, or null.
     */
    suspend fun patchSettings(update: Map<String, Any?>): Settings {
        val payload = buildJsonObject {
            update.forEach { (key, value) -> put(key, value.toJsonPrimitiveOrNull()) }
        }
        val body = HomeRadarJson.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder()
            .url(url("/settings"))
            .patch(body)
            .attachAuth()
            .build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }

    suspend fun postScan(): JsonElement {
        val body = "".toRequestBody(null)
        val request = Request.Builder()
            .url(url("/scan"))
            .post(body)
            .attachAuth()
            .build()
        return HomeRadarJson.parseToJsonElement(executeForBody(request))
    }

    suspend fun claimPairingCode(code: String): PairClaimResult {
        val payload = buildJsonObject { put("code", code) }
        val body = HomeRadarJson.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE)
        val request = Request.Builder()
            .url(url("/pair/claim"))
            .post(body)
            .attachAuth()
            .build()
        return HomeRadarJson.decodeFromString(executeForBody(request))
    }
}

private fun Any?.toJsonPrimitiveOrNull(): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Int -> JsonPrimitive(this)
    is Long -> JsonPrimitive(this)
    is Double -> JsonPrimitive(this)
    else -> JsonPrimitive(this.toString())
}

/** Thrown when the appliance returns a non-2xx response. */
class HomeRadarApiException(val code: Int, val bodyText: String) :
    Exception("HomeRadar API error $code: $bodyText")
