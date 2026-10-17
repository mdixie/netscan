package com.example.wifiinspector

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.channels.Channel
import java.net.ConnectException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.coroutines.coroutineContext

data class WifiNetwork(
    val network: Network,
    val address: String,
    val prefix: Int,
    val gateway: String,
    val dns: List<String>,
    val interfaceName: String,
    val targets: List<String>,
)
data class Finding(val severity: String, val title: String, val evidence: String, val advice: String)
data class Device(val ip: String, val ports: List<Int>, val findings: List<Finding>, val fullScan: Boolean = false)

object PortInfo {
    val services = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS (TCP)",
        80 to "HTTP", 110 to "POP3", 111 to "RPC", 135 to "RPC", 139 to "NetBIOS",
        143 to "IMAP", 443 to "HTTPS", 445 to "SMB", 465 to "SMTP over TLS",
        554 to "RTSP", 631 to "IPP", 993 to "IMAP over TLS", 995 to "POP3 over TLS",
        1433 to "SQL Server", 1883 to "MQTT", 2049 to "NFS", 3306 to "MySQL",
        3389 to "Remote Desktop", 5432 to "PostgreSQL", 5900 to "VNC", 6379 to "Redis",
        8000 to "Alternate web service", 8080 to "Alternate HTTP", 8443 to "Alternate HTTPS",
        8883 to "MQTT over TLS", 9100 to "Printer", 9200 to "Elasticsearch", 27017 to "MongoDB",
    )
    val common = services.keys.sorted()
    fun label(port: Int) = services[port] ?: "Unknown service"
    fun findings(ports: List<Int>): List<Finding> = ports.mapNotNull { port ->
        when (port) {
            21, 23, 110, 143, 1883 -> Finding("Review", "Potential unencrypted service", "TCP $port accepts connections. ${label(port)} is a conventional port label; the protocol and encryption were not verified.", "Check the service configuration. Disable unused access and require encryption; some services support STARTTLS.")
            80, 8080 -> Finding("Review", "Potential HTTP exposure", "TCP $port accepts connections. HTTP and HTTPS redirects were not verified.", "Check whether sensitive pages use HTTPS and whether this listener is needed.")
            3389, 5900 -> Finding("Review", "Potential remote desktop exposure", "TCP $port accepts connections. Service identity and authentication were not verified.", "Restrict remote desktop access to trusted clients and require strong authentication.")
            1433, 3306, 5432, 6379, 9200, 27017 -> Finding("Review", "Potential database exposure", "TCP $port accepts connections. Database identity and access controls were not verified.", "Restrict access to required clients and verify authentication and encryption.")
            139, 445 -> Finding("Review", "Potential file sharing exposure", "TCP $port accepts connections. SMB version and shares were not inspected.", "Review shares and permissions. Disable legacy SMB versions and restrict access.")
            else -> null
        }
    }
}

class Scanner(context: Context) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    fun connectedWifi(): WifiNetwork {
        val network = connectivity.allNetworks.firstOrNull {
            connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        } ?: error("Connect to Wi-Fi before scanning.")
        val links = connectivity.getLinkProperties(network) ?: error("Wi-Fi network details are unavailable.")
        val local = links.linkAddresses.firstOrNull { it.address is Inet4Address }
            ?: error("This version requires an IPv4 Wi-Fi network.")
        val targets = subnetTargets(local.address.hostAddress!!, local.prefixLength)
        return WifiNetwork(network, local.address.hostAddress!!, local.prefixLength,
            links.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress ?: "Unavailable",
            links.dnsServers.mapNotNull { it.hostAddress }, links.interfaceName ?: "Unavailable", targets)
    }

    suspend fun discover(wifi: WifiNetwork, progress: suspend (String, Device?) -> Unit) = withContext(Dispatchers.IO) {
        val queue = Channel<String>(Channel.UNLIMITED)
        wifi.targets.forEach { queue.trySend(it) }
        queue.close()
        coroutineScope {
            repeat(8) {
                launch {
                    for (ip in queue) {
                        var responded = false
                        val open = mutableListOf<Int>()
                        for (port in PortInfo.common) {
                            coroutineContext.ensureActive()
                            when (probe(wifi.network, ip, port)) {
                                Probe.OPEN -> { responded = true; open.add(port) }
                                Probe.REFUSED -> responded = true
                                Probe.NO_RESPONSE -> Unit
                            }
                        }
                        progress(ip, if (responded) Device(ip, open, PortInfo.findings(open)) else null)
                    }
                }
            }
        }
    }

    suspend fun fullScan(wifi: WifiNetwork, ip: String, progress: suspend (Int) -> Unit): Device = withContext(Dispatchers.IO) {
        require(ip in wifi.targets) { "Device is outside the selected Wi-Fi scan range." }
        val queue = Channel<Int>(Channel.UNLIMITED)
        (1..65535).forEach { queue.trySend(it) }
        queue.close()
        val open = java.util.concurrent.ConcurrentLinkedQueue<Int>()
        coroutineScope {
            repeat(32) {
                launch {
                    for (port in queue) {
                        coroutineContext.ensureActive()
                        if (probe(wifi.network, ip, port) == Probe.OPEN) open.add(port)
                        progress(port)
                    }
                }
            }
        }
        val sorted = open.toList().sorted()
        Device(ip, sorted, PortInfo.findings(sorted), fullScan = true)
    }

    private enum class Probe { OPEN, REFUSED, NO_RESPONSE }
    private fun probe(network: Network, ip: String, port: Int): Probe = try {
        network.socketFactory.createSocket().use { socket ->
            socket.connect(InetSocketAddress(ip, port), 350)
        }
        Probe.OPEN
    } catch (e: ConnectException) {
        if (e.message.orEmpty().contains("refused", ignoreCase = true)) Probe.REFUSED else Probe.NO_RESPONSE
    } catch (_: java.io.IOException) {
        Probe.NO_RESPONSE
    }
}

/** Limit scans to at most 1,022 hosts; never silently scan a truncated subnet. */
fun subnetTargets(address: String, prefix: Int): List<String> {
    require(prefix in 22..30) { "Automatic scanning supports IPv4 /22 through /30 networks (up to 1,022 hosts)." }
    val bytes = InetAddress.getByName(address).address
    require(bytes.size == 4)
    val ip = bytes.fold(0L) { value, byte -> (value shl 8) or (byte.toLong() and 255) }
    val mask = (0xffffffffL shl (32 - prefix)) and 0xffffffffL
    val first = ip and mask
    val last = first or (mask xor 0xffffffffL)
    return (first + 1 until last).map { value ->
        listOf(24, 16, 8, 0).joinToString(".") { shift -> ((value shr shift) and 255).toString() }
    }.filter { it != address }
}
