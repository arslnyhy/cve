from comfy import high


@high(
    name='rule_cve20243384',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running'
    ),
)
def rule_cve20243384(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3384 in PAN-OS configurations.
    The vulnerability allows a remote attacker to reboot PAN-OS firewalls when receiving Windows 
    New Technology LAN Manager (NTLM) packets from Windows servers. Repeated attacks eventually 
    cause the firewall to enter maintenance mode, requiring manual intervention.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 8.1.', 'sw-version: 9.0.', 'sw-version: 9.1.', 'sw-version: s10.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if NTLM authentication is enabled
    config = commands.show_running_config
    if 'ntlm' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3384. "
        "The device is running a vulnerable version and has NTLM authentication enabled, "
        "making it susceptible to DoS attacks via malformed NTLM packets. "
        "Upgrade to a fixed version: 8.1.24+, 9.0.17+, 9.1.15-h1+, 10.0.12+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3384"
    )
