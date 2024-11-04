from comfy import high

@high(
    name='rule_cve202420303',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_ap_status='show ap status | i Flex',
        show_mdns_sd_summary='show mdns-sd summary'
    ),
)
def rule_cve202420303(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20303 vulnerability in Cisco IOS XE Software for Wireless LAN Controllers.
    The vulnerability is due to improper management of mDNS client entries, which can lead to a DoS condition.
    This test verifies if the mDNS gateway feature is enabled and if there are any APs in FlexConnect mode.
    If both conditions are met, the device is considered vulnerable.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.2.x versions
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        # 17.3.x versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x',
        '17.3.1z', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c',
        '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        # 17.4.x versions
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        # 17.5.x versions
        '17.5.1', '17.5.1a',
        # 17.6.x versions
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.5a',
        # 17.7.x versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        # 17.8.x versions
        '17.8.1', '17.8.1a',
        # 17.9.x versions
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.1y1',
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if there are any APs in FlexConnect mode
    ap_status_output = commands.show_ap_status
    ap_in_flexconnect_mode = 'FlexConnect' in ap_status_output

    # Check if the mDNS gateway feature is enabled
    mdns_summary_output = commands.show_mdns_sd_summary
    mdns_gateway_enabled = 'mDNS Gateway: Enabled' in mdns_summary_output

    # Assert that the device is not vulnerable
    # If both conditions are true, the device is vulnerable
    assert not (ap_in_flexconnect_mode and mdns_gateway_enabled), (
        f"Device {device.name} is vulnerable to CVE-2024-20303. "
        "The device is running a vulnerable version AND has mDNS gateway enabled with APs in FlexConnect mode. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-mdns-dos-4hv6pBGf"
    )
