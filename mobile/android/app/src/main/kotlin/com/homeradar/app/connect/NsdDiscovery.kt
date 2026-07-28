package com.homeradar.app.connect

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

/** One resolved candidate appliance found via mDNS/NSD discovery. */
data class DiscoveredHost(
    val name: String,
    /** "host:port", ready to drop straight into the address field. */
    val address: String,
)

private const val SERVICE_TYPE = "_http._tcp."

/**
 * Discovers HomeRadar-looking `_http._tcp` services on the local network via
 * Android's [NsdManager]. Filters to service names that look like
 * "homeradar" (case-insensitive) since a household LAN can advertise many
 * unrelated `_http._tcp` services (printers, smart TVs, etc.) that would
 * otherwise clutter the list.
 *
 * The flow stays open -- emitting a [DiscoveredHost] each time one resolves
 * -- until the collecting coroutine is cancelled (e.g. via
 * `withTimeoutOrNull` in the caller), at which point discovery is stopped.
 */
fun discoverHomeRadarHosts(context: Context): Flow<DiscoveredHost> = callbackFlow {
    val nsdManager = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager

    val discoveryListener = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(serviceType: String) = Unit
        override fun onDiscoveryStopped(serviceType: String) = Unit
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = Unit

        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            close()
        }

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            if (!serviceInfo.serviceName.contains("homeradar", ignoreCase = true)) return

            // NsdManager requires a fresh ResolveListener per resolve call, so this
            // can't be hoisted out and shared across onServiceFound invocations.
            nsdManager.resolveService(
                serviceInfo,
                object : NsdManager.ResolveListener {
                    override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                        // Ignore -- this candidate just won't be offered.
                    }

                    override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                        val host = serviceInfo.host?.hostAddress ?: return
                        trySend(DiscoveredHost(name = serviceInfo.serviceName, address = "$host:${serviceInfo.port}"))
                    }
                },
            )
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo) = Unit
    }

    nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)

    awaitClose {
        try {
            nsdManager.stopServiceDiscovery(discoveryListener)
        } catch (_: IllegalArgumentException) {
            // Discovery was already stopped (or never fully started) -- fine to ignore.
        }
    }
}
