from comfy import high


@high(
    name='rule_cve20243383',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match "cloud-identity-engine"'
    ),
)
def rule_cve20243383(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3383 in PAN-OS configurations.
    The vulnerability in how PAN-OS software processes data received from Cloud Identity Engine (CIE) agents 
    enables modification of User-ID groups. This impacts user access to network resources where users may be 
    inappropriately denied or allowed access to resources based on existing Security Policy rules.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable versions
    vulnerable_versions = [
        'sw-version: 10.1', 'sw-version: 10.2', 'sw-version: 11.0'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if Cloud Identity Engine (CIE) is enabled
    config = commands.show_running_config
    if 'cloud-identity-engine' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3383. "
        "The device is running a vulnerable version with Cloud Identity Engine (CIE) enabled, making it susceptible "
        "to unauthorized modification of User-ID groups which could impact access control. "
        "Upgrade to a fixed version: PAN-OS 10.1.11+, 10.2.5+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3383"
    )
