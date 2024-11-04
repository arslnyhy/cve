from comfy import high

@high(
    name='rule_cve202420304',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_install_active='show install active summary | include mcast',
        show_lpts_pifib_hardware='show lpts pifib hardware entry brief location | include 33433',
        show_lpts_pifib_entry='show lpts pifib entry brief | include 33433'
    ),
)
def rule_cve202420304(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20304 vulnerability in Cisco IOS XR devices.
    The vulnerability allows an attacker to exhaust UDP packet memory by exploiting
    the Mtrace2 feature. This test verifies if the device is running a vulnerable version
    and if the multicast RPM is active and Mtrace2 processing is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.12', '7.8.2', '7.8.22',
        # 7.9.x versions
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1', '7.10.2',
        # 7.11.x versions
        '7.11.1', '7.11.2',
        # 24.x versions
        '24.1.1', '24.1.2',
        '24.2.1', '24.2.11'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the multicast RPM is active
    # If the command output is not empty, the multicast RPM is active
    multicast_rpm_active = 'mcast' in commands.show_install_active
    
    # Check if Mtrace2 processing is enabled by verifying LPTS entries for port 33433
    # If either command returns a non-empty output, Mtrace2 processing is enabled
    mtrace2_processing_enabled = 'any' in commands.show_lpts_pifib_hardware or 'any' in commands.show_lpts_pifib_entry

    # Assert that the device is not vulnerable
    # The device is considered vulnerable if the multicast RPM is active, Mtrace2 processing is enabled,
    # and the packet counts for mld or igmp are unusually high
    assert not (multicast_rpm_active and mtrace2_processing_enabled), (
        f"Device {device.name} is vulnerable to CVE-2024-20304. "
        "The device is running a vulnerable version AND has multicast RPM active with Mtrace2 processing enabled. "
        "Check 'show packet-memory summary' for packet counts for mld and igmp. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pak-mem-exhst-3ke9FeFy"
    )
