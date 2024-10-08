@high(
    name='rule_cve202420446',
    platform=['cisco_nxos'],
    commands=dict(
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

    # Check if the DHCPv6 relay agent is enabled
    dhcp_relay_enabled = 'ipv6 dhcp relay' in commands.show_dhcp_relay
    # Check if there is at least one IPv6 address configured
    ipv6_address_configured = bool(commands.show_ipv6_interface.strip())

    # Assert that the device is not vulnerable
    # The device is vulnerable if both conditions are true
    assert not (dhcp_relay_enabled and ipv6_address_configured), (
        f"Device {device.name} is vulnerable to CVE-2024-20446. "
        "DHCPv6 relay agent is enabled and an IPv6 address is configured."
    )
