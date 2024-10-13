from comfy import high

@high(
    name='rule_cve202420259',
    platform=['cisco_xe'],
    commands=dict(
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
        "Both DHCP snooping and endpoint analytics are enabled."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dhcp-dos-T3CXPO9z"
    )
