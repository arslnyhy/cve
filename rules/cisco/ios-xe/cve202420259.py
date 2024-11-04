from comfy import high

@high(
    name='rule_cve202420259',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_dhcp_snooping='show running-config | include dhcp snooping vlan',
        show_endpoint_analytics='show avc sd-service info detailed | include isLearnMacOnFif|isDcsEnabled'
    ),
)
def rule_cve202420259(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco IOS XE devices
    related to DHCP snooping and endpoint analytics. The vulnerability can cause
    a denial of service (DoS) if both features are enabled.

    CVE-2024-20259 describes a vulnerability where a crafted DHCP request can
    cause the device to reload unexpectedly if DHCP snooping and endpoint analytics
    are both enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.1.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
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
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.6', '17.6.6a',
        '17.6.5a',
        # 17.7.x versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        # 17.8.x versions
        '17.8.1', '17.8.1a',
        # 17.9.x versions
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.4', '17.9.1y1', '17.9.4a',
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW',
        # 17.12.x versions
        '17.12.1', '17.12.1w', '17.12.1a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if DHCP snooping is enabled by examining the command output
    dhcp_snooping_enabled = 'ip dhcp snooping vlan' in commands.show_dhcp_snooping

    # Check if endpoint analytics is enabled by looking for specific flags in the command output
    endpoint_analytics_enabled = (
        '"isDcsEnabled": true' in commands.show_endpoint_analytics and
        '"isLearnMacOnFif": true' in commands.show_endpoint_analytics
    )

    # Assert that both features are not enabled simultaneously
    # If both are enabled, this device is vulnerable to the described DoS attack
    assert not (dhcp_snooping_enabled and endpoint_analytics_enabled), (
        f"Device {device.name} is vulnerable to CVE-2024-20259. "
        "The device is running a vulnerable version AND has both DHCP snooping and endpoint analytics enabled. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dhcp-dos-T3CXPO9z"
    )
