package com.homeradar.core.net

/**
 * The one place the pairing-token header name lives. If HomeRadar's API ever
 * switches this app over to `Authorization: Bearer <token>` instead, this is
 * the only line that needs to change -- every request already funnels through
 * [com.homeradar.core.net.HomeRadarClient]'s single `attachAuth()` attach-point.
 */
const val AUTH_HEADER_NAME: String = "X-HomeRadar-Token"

/**
 * Supplies the current pairing token, if any. Returns null when the app has
 * not yet paired with an appliance (or the user has signed out), in which
 * case requests are sent with no auth header at all.
 */
interface TokenProvider {
    fun currentToken(): String?
}
