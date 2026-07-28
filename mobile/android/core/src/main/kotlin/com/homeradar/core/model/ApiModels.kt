package com.homeradar.core.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Shared [Json] instance for all decoding in this module.
 *
 * [ignoreUnknownKeys] is REQUIRED (not optional): several backend response shapes
 * carry fields the app doesn't model yet (e.g. `Device.fingerprint`,
 * `Dashboard.traffic`/`inventory`). Without this flag, decoding any real
 * response would throw. See ApiModelsDecodingTest for a regression guard
 * proving this setting is actually load-bearing.
 */
val HomeRadarJson: Json = Json {
    ignoreUnknownKeys = true
}

/**
 * GET /status
 */
@Serializable
data class Status(
    val device_count: Int,
    val open_alert_count: Int,
    val security_score: Int,
    val dns_enabled: Boolean,
    val blocklist_domains: Int,
)

/**
 * A device row as returned by GET /devices, GET /devices/{id}, and embedded in
 * GET /dashboard and the websocket snapshot push.
 *
 * Deliberately omits `fingerprint`: present in the real JSON, unused by any
 * screen this pass. Safe to omit given [HomeRadarJson]'s ignoreUnknownKeys=true.
 */
@Serializable
data class Device(
    val id: Int,
    val mac: String,
    val ip: String? = null,
    val hostname: String? = null,
    val vendor: String? = null,
    val model: String? = null,
    val device_type: String,
    val fingerprint_confidence: Double = 0.0,
    val open_ports: List<Int> = emptyList(),
    val services: List<String> = emptyList(),
    val discovery_sources: List<String> = emptyList(),
    val trust_score: Int,
    val is_authorized: Int,
    val first_seen: String,
    val last_seen: String,
)

/**
 * An alert row as returned by every GET/list/dashboard/websocket path. On these
 * paths the backend does `dict(row)` straight from sqlite with no Pydantic
 * model, so `is_resolved` arrives as a raw JSON int (0/1), NOT a boolean.
 *
 * Do NOT reuse this class for the `PATCH /alerts/{id}` response -- that one
 * endpoint has a real Pydantic model and returns `is_resolved` as an actual
 * JSON boolean. Use [AlertResolveResult] for that response instead.
 */
@Serializable
data class Alert(
    val id: Int,
    val device_id: Int? = null,
    val severity: String,
    val title: String,
    val description: String? = null,
    val is_resolved: Int,
    val created_at: String,
)

/**
 * The response body of `PATCH /alerts/{id}`, which -- unlike every other alert
 * response in this API -- goes through a real Pydantic model and therefore
 * serializes `is_resolved` as a genuine JSON boolean, not an int.
 */
@Serializable
data class AlertResolveResult(
    val id: Int,
    val is_resolved: Boolean,
)

/**
 * GET /dashboard. Omits `traffic`/`inventory`: present in the real JSON,
 * unused this pass, safe to omit given ignoreUnknownKeys=true.
 */
@Serializable
data class Dashboard(
    val status: Status,
    val devices: List<Device>,
    val alerts: List<Alert>,
)

/**
 * The smaller status shape embedded in the websocket snapshot push. This is
 * NOT the same shape as the REST [Status] above -- it omits
 * `dns_enabled`/`blocklist_domains` -- so it gets its own class rather than
 * being conflated with [Status].
 */
@Serializable
data class SnapshotStatus(
    val device_count: Int,
    val open_alert_count: Int,
    val security_score: Int,
)

/**
 * A full-state push frame sent over the dashboard websocket.
 */
@Serializable
data class SnapshotMessage(
    val type: String,
    val status: SnapshotStatus,
    val devices: List<Device>,
    val alerts: List<Alert>,
)

/**
 * GET /settings
 */
@Serializable
data class Settings(
    val household_name: String,
    val digest_email: String,
    val dns_upstream: String,
    val notifications_enabled: Boolean,
    val dns_enabled: Boolean,
    val setup_complete: Boolean,
)

/**
 * POST /pair/claim response.
 */
@Serializable
data class PairClaimResult(
    val token: String,
)
