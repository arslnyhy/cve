from comfy import high

@high(
    name='rule_cve202420304',
    platform=['cisco_xr'],
    commands=dict(
        show_install_active='show install active summary | include mcast',
        show_lpts_pifib_hardware='show lpts pifib hardware entry brief location | include 33433',
        show_lpts_pifib_entry='show lpts pifib entry brief | include 33433',
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
    multicast_rpm_active = 'mcast' in commands.show_install_active
    
    # Check if Mtrace2 processing is enabled by verifying LPTS entries for port 33433
    # If either command returns a non-empty output, Mtrace2 processing is enabled
    mtrace2_processing_enabled = 'any' in commands.show_lpts_pifib_hardware or 'any' in commands.show_lpts_pifib_entry

    # Assert that the device is not vulnerable
    # The device is considered vulnerable if the multicast RPM is active, Mtrace2 processing is enabled,
    # and the packet counts for mld or igmp are unusually high
    assert not (multicast_rpm_active and mtrace2_processing_enabled), (
        f"Device {device.name} is vulnerable to CVE-2024-20304. "
        f"Multicast RPM is active, Mtrace2 processing is enabled. "
        f"Check 'show packet-memory summary' for packet counts for mld and igmp. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-pak-mem-exhst-3ke9FeFy"
    )
