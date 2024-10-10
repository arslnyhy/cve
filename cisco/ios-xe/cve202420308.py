@high(
    name='rule_cve202420308',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(
        show_running_config='show running-config',
        show_udp='show udp'
    ),
)
def rule_cve202420308(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20307 vulnerability on Cisco IOS and IOS XE devices.
    The vulnerability is present if IKEv1 fragmentation is enabled and the 'buffers huge size'
    is set to a value greater than 32,767. This can lead to a heap overflow and a denial of service.
    """

    # Check if IKEv1 fragmentation is enabled
    ikev1_fragmentation_enabled = 'crypto isakmp fragmentation' in configuration
    assert not ikev1_fragmentation_enabled, "IKEv1 fragmentation is enabled, which is part of the vulnerability condition."

    # Check if any IKEv1 VPN is configured by checking open UDP ports
    udp_output = commands.show_udp
    ikev1_ports = ['500', '4500', '848']
    ikev1_configured = any(port in udp_output for port in ikev1_ports)
    assert not ikev1_configured, "IKEv1 VPN is configured, which is part of the vulnerability condition."

    # Check if 'buffers huge size' is set to a value greater than 32,767
    buffers_huge_config = 'buffers huge size' in configuration
    if buffers_huge_config:
        # Extract the value of 'buffers huge size'
        for line in configuration.splitlines():
            if 'buffers huge size' in line:
                _, size = line.split()
                size = int(size)
                # Assert that the size is not greater than 32,767
                assert size <= 32767, f"buffers huge size is set to {size}, which is greater than 32,767 and part of the vulnerability condition."

    # If all conditions are met, the device is vulnerable
    if ikev1_fragmentation_enabled and ikev1_configured and buffers_huge_config and size > 32767:
        assert False, "Device is vulnerable to CVE-2024-20307 due to IKEv1 fragmentation and buffers huge size configuration."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz"