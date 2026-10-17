package com.example.wifiinspector

import org.junit.Assert.*
import org.junit.Test

class SubnetTest {
    @Test fun excludesNetworkBroadcastAndOwnAddress() {
        val targets = subnetTargets("192.168.4.2", 30)
        assertEquals(listOf("192.168.4.1"), targets)
    }
    @Test fun handlesNonAlignedSubnets() {
        val targets = subnetTargets("10.0.5.7", 23)
        assertEquals(509, targets.size)
        assertEquals("10.0.4.1", targets.first())
        assertEquals("10.0.5.254", targets.last())
        assertFalse(targets.contains("10.0.5.7"))
    }
    @Test fun rejectsLargeNetworks() {
        assertThrows(IllegalArgumentException::class.java) { subnetTargets("10.0.0.1", 16) }
    }
    @Test fun refusesIpv6() {
        assertThrows(IllegalArgumentException::class.java) { subnetTargets("::1", 24) }
    }
    @Test fun findingsNeverClaimConfirmedVulnerabilities() {
        val findings = PortInfo.findings(listOf(23, 443, 6379))
        assertEquals(2, findings.size)
        assertTrue(findings.all { it.severity == "Review" && it.evidence.contains("not verified") })
    }
}
