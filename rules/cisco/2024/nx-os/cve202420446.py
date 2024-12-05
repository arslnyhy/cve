from comfy import high

@high(
    name='rule_cve202420446',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_dhcp_relay='show run all | include "^ipv6 dhcp relay"',
        show_ipv6_interface='show ipv6 interface brief'
    ),
)
def rule_cve202420446(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20446 vulnerability in Cisco NX-OS devices.
    The vulnerability is present if the DHCPv6 relay agent is enabled and at least
    one IPv6 address is configured on the device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 8.x versions
        '8.2(11)',
        
        # 9.x versions
        '9.3(9)',
        
        # 10.x versions
        '10.2(1)', '10.2(1q)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the DHCPv6 relay agent is enabled
    dhcp_relay_enabled = 'ipv6 dhcp relay' in commands.show_dhcp_relay
    
    # Check if there is at least one IPv6 address configured
    ipv6_address_configured = 'Interface' in commands.show_ipv6_interface

    # Assert that the device is not vulnerable
    # The device is vulnerable if both conditions are true
    assert not (dhcp_relay_enabled and ipv6_address_configured), (
        f"Device {device.name} is vulnerable to CVE-2024-20446. "
        "The device is running a vulnerable version AND has DHCPv6 relay agent enabled with IPv6 addresses configured. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dhcp6-relay-dos-znEAA6xn"
    )
