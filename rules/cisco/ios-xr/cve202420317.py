from comfy import high

@high(
    name='rule_cve202420317',
    platform=['cisco_xr'],
    commands=dict(
        show_running_config='show running-config | include l2transport',
        show_voq_stats='show controllers npu stats voq ingress interface'
    ),
)
def rule_cve202420317(configuration, commands, device, devices):
    """
    This rule checks for the presence of Layer 2 Ethernet services on Cisco IOS XR devices,
    which are vulnerable to CVE-2024-20317. The vulnerability can cause a denial of service
    by dropping critical priority packets if specific Ethernet frames are incorrectly classified.
    """

    # Check if the device is configured with Layer 2 Ethernet services
    # If the command output contains 'l2transport', the device is affected by the vulnerability
    if 'l2transport' in commands.show_running_config:
        # Assert failure if Layer 2 services are found, indicating the device is vulnerable
        assert False, (
            f"Device {device.name} is configured with Layer 2 Ethernet services, "
            "making it vulnerable to CVE-2024-20317. "
            "Consider upgrading to a fixed software release."
        )

    # Optionally, you can check for VOQ statistics to see if there are any signs of packet drops
    # This is an additional check to monitor if the vulnerability is being exploited
    voq_stats = commands.show_voq_stats
    if 'TC_7' in voq_stats and 'DroppedPkts' in voq_stats:
        # Extract the number of dropped packets for traffic class 7
        dropped_packets = int(voq_stats.split('TC_7')[1].split()[2])
        if dropped_packets > 0:
            # Assert failure if there are dropped packets in TC_7, indicating potential exploitation
            assert False, (
                f"Device {device.name} shows dropped packets in TC_7 VOQ, "
                "indicating potential exploitation of CVE-2024-20317. "
                "Immediate action is recommended."
                "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-l2services-2mvHdNuC"
            )

    # If no Layer 2 services are configured and no packet drops are detected, the device is not vulnerable
    assert True, f"Device {device.name} is not configured with Layer 2 Ethernet services and shows no signs of exploitation."
