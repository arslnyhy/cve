@high(
    name='rule_cve202420304',
    platform=['cisco_xr'],
    commands=dict(
        show_install_active='show install active summary | include mcast',
        show_lpts_pifib_hardware='show lpts pifib hardware entry brief location | include 33433',
        show_lpts_pifib_entry='show lpts pifib entry brief | include 33433',
        show_packet_memory='show packet-memory summary'
    ),
)
def rule_cve202420304(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20304 vulnerability in Cisco IOS XR devices.
    The vulnerability allows an attacker to exhaust UDP packet memory by exploiting
    the Mtrace2 feature. This test verifies if the device is vulnerable by checking
    if the multicast RPM is active and if Mtrace2 processing is enabled.
    """

    # Check if the multicast RPM is active
    # If the command output is not empty, the multicast RPM is active
    multicast_rpm_active = bool(commands.show_install_active.strip())
    
    # Check if Mtrace2 processing is enabled by verifying LPTS entries for port 33433
    # If either command returns a non-empty output, Mtrace2 processing is enabled
    mtrace2_processing_enabled = bool(commands.show_lpts_pifib_hardware.strip()) or bool(commands.show_lpts_pifib_entry.strip())

    # Check the packet memory usage for mld and igmp processes
    # If the packet count for these processes is high, it may indicate the vulnerability is being exploited
    packet_memory_lines = commands.show_packet_memory.splitlines()
    mld_packet_count = 0
    igmp_packet_count = 0
    for line in packet_memory_lines:
        if 'mld' in line:
            mld_packet_count = int(line.split()[2])
        elif 'igmp' in line:
            igmp_packet_count = int(line.split()[2])

    # Assert that the device is not vulnerable
    # The device is considered vulnerable if the multicast RPM is active, Mtrace2 processing is enabled,
    # and the packet counts for mld or igmp are unusually high
    assert not (multicast_rpm_active and mtrace2_processing_enabled and (mld_packet_count > 1000 or igmp_packet_count > 1000)), (
        f"Device {device.name} is vulnerable to CVE-2024-20304. "
        f"Multicast RPM is active, Mtrace2 processing is enabled, "
        f"and packet counts are high (MLD: {mld_packet_count}, IGMP: {igmp_packet_count})."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pak-mem-exhst-3ke9FeFy"
    )
