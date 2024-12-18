from comfy import high


@high(
    name='rule_cve20243385',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match gtp'
    ),
)
def rule_cve20243385(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3385 in PAN-OS configurations.
    The vulnerability allows a remote attacker to reboot hardware-based firewalls when GTP Security 
    is disabled. Repeated attacks eventually cause the firewall to enter maintenance mode, requiring 
    manual intervention.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 9.0.', 'sw-version: 9.1.', 'sw-version: 10.1.', 'sw-version: 10.2.', 'sw-version: 11.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if GTP Security is disabled (in PAN-OS, this would be 'enabled no')
    config = commands.show_running_config
    if 'gtp' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3385. "
        "The device is running a vulnerable version and has GTP Security disabled, "
        "making it susceptible to DoS attacks. "
        "Upgrade to a fixed version: 9.0.17-h4+, 9.1.17+, 10.1.12+, 10.2.8+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3385"
    )
