package com.example.wifiinspector

import android.app.Application
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class ScanState(
    val network: WifiNetwork? = null,
    val devices: List<Device> = emptyList(),
    val busy: Boolean = false,
    val status: String = "Ready to scan your Wi-Fi.",
    val completed: Int = 0,
    val total: Int = 0,
    val startedAt: String = "",
)

class ScanViewModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(ScanState())
        private set
    private val scanner = Scanner(application)
    private var job: Job? = null

    fun discover() {
        if (state.busy) return
        job = viewModelScope.launch {
            try {
                val wifi = scanner.connectedWifi()
                state = ScanState(network = wifi, busy = true, status = "Checking common TCP ports…",
                    total = wifi.targets.size, startedAt = java.time.Instant.now().toString())
                scanner.discover(wifi) { _, device ->
                    withContext(Dispatchers.Main) {
                        state = state.copy(completed = state.completed + 1,
                            devices = if (device == null) state.devices else (state.devices + device).sortedBy { d ->
                                d.ip.split('.').fold(0L) { value, octet -> value * 256 + octet.toInt() }
                            })
                    }
                }
                require(scanner.connectedWifi().network == wifi.network) { "Wi-Fi changed during the scan. Results may be incomplete; start a new scan." }
                state = state.copy(busy = false, status = "Scan complete. ${state.devices.size} devices responded.")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                state = state.copy(busy = false, status = e.message ?: "Scan failed.")
            }
        }
    }

    fun fullScan(ip: String) {
        if (state.busy) return
        val wifi = state.network ?: return
        job = viewModelScope.launch {
            state = state.copy(busy = true, completed = 0, total = 65535, status = "Scanning all TCP ports on $ip…")
            try {
                require(scanner.connectedWifi().network == wifi.network) { "Wi-Fi changed. Start a new discovery scan." }
                val result = scanner.fullScan(wifi, ip) {
                    withContext(Dispatchers.Main) { state = state.copy(completed = state.completed + 1) }
                }
                state = state.copy(busy = false, status = "Full TCP scan complete for $ip.",
                    devices = state.devices.map { if (it.ip == ip) result else it })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                state = state.copy(busy = false, status = e.message ?: "Scan failed.")
            }
        }
    }

    fun cancel() {
        job?.cancel()
        state = state.copy(busy = false, status = "Scan cancelled. Completed device results retained; an unfinished full scan is discarded.")
    }

    fun report(): String = JSONObject().apply {
        put("scanStartedAtUtc", state.startedAt)
        put("reportCreatedAtUtc", java.time.Instant.now().toString())
        put("status", state.status)
        put("completedWorkItems", state.completed)
        put("totalWorkItems", state.total)
        put("limitations", "IPv4 TCP only; device inventory may be incomplete. Service names are port conventions, not verified identities. Findings are potential exposures, not confirmed vulnerabilities. No CVE lookup performed.")
        state.network?.let { wifi ->
            put("network", JSONObject().apply {
                put("localAddress", wifi.address); put("prefix", wifi.prefix)
                put("gateway", wifi.gateway); put("dns", JSONArray(wifi.dns))
                put("interface", wifi.interfaceName)
            })
        }
        put("devices", JSONArray().apply {
            state.devices.forEach { device ->
                put(JSONObject().apply {
                    put("ip", device.ip)
                    put("scanScope", if (device.fullScan) "TCP ports 1–65535" else "Common TCP ports")
                    put("openTcpPorts", JSONArray(device.ports))
                    put("findings", JSONArray().apply {
                        device.findings.forEach { finding -> put(JSONObject().apply {
                            put("severity", finding.severity); put("title", finding.title)
                            put("evidence", finding.evidence); put("advice", finding.advice)
                        }) }
                    })
                })
            }
        })
    }.toString(2)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { InspectorScreen() } }
    }
}

@Composable
fun InspectorScreen(model: ScanViewModel = viewModel()) {
    val state = model.state
    val context = LocalContext.current
    var authorized by rememberSaveable { mutableStateOf(false) }
    var fullScanTarget by remember { mutableStateOf<String?>(null) }
    Surface(modifier = Modifier.fillMaxSize()) {
        LazyColumn(modifier = Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding(),
            contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Text("Wi-Fi Inspector", style = MaterialTheme.typography.headlineLarge)
                Text("Local network discovery • No root required", style = MaterialTheme.typography.bodyMedium)
            }
            item {
                Text("Only scan networks you own or are authorized to assess. Scans generate traffic and may trigger monitoring alerts.")
                Row {
                    Checkbox(checked = authorized, onCheckedChange = { authorized = it }, enabled = !state.busy)
                    Text("I have permission to scan this network.", modifier = Modifier.padding(top = 12.dp))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = model::discover, enabled = authorized && !state.busy) { Text("Discover devices") }
                    if (state.busy) OutlinedButton(onClick = model::cancel) { Text("Stop") }
                }
            }
            item {
                Text(state.status)
                if (state.total > 0) Text("${state.completed} / ${state.total} checks completed")
                if (state.busy && state.total > 0) LinearProgressIndicator(
                    progress = { state.completed.toFloat() / state.total }, modifier = Modifier.fillMaxWidth())
            }
            state.network?.let { wifi ->
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Connected Wi-Fi", style = MaterialTheme.typography.titleMedium)
                            Text("Phone: ${wifi.address}/${wifi.prefix}\nGateway: ${wifi.gateway}\nDNS: ${wifi.dns.joinToString()}\nInterface: ${wifi.interfaceName}")
                            Text("Wi-Fi name and device MAC/vendor information are restricted by Android and are not collected in this version.")
                        }
                    }
                }
            }
            item {
                Text("Results can miss sleeping devices, filtered hosts, UDP-only devices, and clients isolated by the router. Your phone is excluded. No findings does not mean a device is secure.",
                    style = MaterialTheme.typography.bodySmall)
                if (state.network != null) TextButton(onClick = {
                    context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_SUBJECT, "Wi-Fi Inspector report")
                        putExtra(Intent.EXTRA_TEXT, model.report())
                    }, "Share JSON report"))
                }, enabled = !state.busy) { Text("Share report") }
            }
            items(state.devices, key = { it.ip }) { device ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(device.ip, style = MaterialTheme.typography.titleLarge)
                        Text(if (device.fullScan) "All TCP ports checked" else "Common TCP ports checked")
                        if (device.ports.isEmpty()) Text("Device responded, but no checked TCP ports were open.")
                        device.ports.forEach { port -> Text("$port / TCP — ${PortInfo.label(port)} (port convention)") }
                        device.findings.forEach { finding ->
                            HorizontalDivider()
                            Text("${finding.severity}: ${finding.title}", style = MaterialTheme.typography.titleSmall)
                            Text(finding.evidence)
                            Text(finding.advice, style = MaterialTheme.typography.bodySmall)
                        }
                        OutlinedButton(onClick = { fullScanTarget = device.ip }, enabled = authorized && !state.busy) {
                            Text("Scan all TCP ports")
                        }
                    }
                }
            }
        }
    }
    fullScanTarget?.let { ip ->
        AlertDialog(onDismissRequest = { fullScanTarget = null }, title = { Text("Full TCP scan of $ip") },
            text = { Text("Checks ports 1–65535 with up to 32 simultaneous connections. This can take several minutes and generate substantial traffic.") },
            confirmButton = { TextButton(onClick = { fullScanTarget = null; model.fullScan(ip) }) { Text("Start scan") } },
            dismissButton = { TextButton(onClick = { fullScanTarget = null }) { Text("Cancel") } })
    }
}
