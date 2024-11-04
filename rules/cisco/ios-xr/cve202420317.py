from comfy import high

@high(
    name='rule_cve202420317',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include l2transport',
        show_voq_stats='show controllers npu stats voq ingress interface'
    ),
)
def rule_cve202420317(configuration, commands, device, devices):
    """
    This rule checks for the presence of Layer 2 Ethernet services on Cisco IOS XR devices,
    which are vulnerable to CVE-2024-20317. The vulnerability can cause a denial of service
    by dropping critical priority packets if specific Ethernet frames are incorrectly classified.
    The test verifies if the device is running a vulnerable version and has Layer 2 services configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2', '7.8.22',
        # 7.9.x versions
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the device is configured with Layer 2 Ethernet services
    l2_services_enabled = 'l2transport' in commands.show_running_config

    # If Layer 2 services are enabled, check for potential exploitation
    if l2_services_enabled:
        # Check VOQ statistics for signs of packet drops
        voq_stats = commands.show_voq_stats
        if 'TC_7' in voq_stats and 'DroppedPkts' in voq_stats:
            try:
                # Extract the number of dropped packets for traffic class 7
                dropped_packets = int(voq_stats.split('TC_7')[1].split()[2])
                if dropped_packets > 0:
                    # Assert failure if there are dropped packets in TC_7, indicating potential exploitation
                    assert False, (
                        f"Device {device.name} is vulnerable to CVE-2024-20317. "
                        "The device is running a vulnerable version, has Layer 2 Ethernet services enabled, "
                        "AND shows dropped packets in TC_7 VOQ, indicating potential exploitation. "
                        "Immediate action is recommended. "
                        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-l2services-2mvHdNuC"
                    )
            except (IndexError, ValueError):
                # If we can't parse the dropped packets count, still warn about L2 services
                pass

        # Assert failure if Layer 2 services are found, indicating the device is vulnerable
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2024-20317. "
            "The device is running a vulnerable version AND is configured with Layer 2 Ethernet services. "
            "Consider upgrading to a fixed software release. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-l2services-2mvHdNuC"
        )
