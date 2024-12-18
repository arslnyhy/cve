from comfy import high


@high(
    name='rule_cve20245916',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_server_profiles='show config running | match "server-profile"'
    ),
)
def rule_cve20245916(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5916 in PAN-OS devices.
    The vulnerability allows read-only administrators to access secrets, passwords, and tokens 
    configured in server profiles through the config log.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable versions
    vulnerable_versions = [
        'sw-version: 10.2.', 'sw-version: 11.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if server profiles are configured
    config = commands.show_server_profiles
    has_server_profiles = 'server-profile' in config

    # Assert that the device is not vulnerable
    assert not has_server_profiles, (
        f"Device {device.name} is vulnerable to CVE-2024-5916. "
        "The device is running a vulnerable version AND has server profiles configured, "
        "which could expose secrets, passwords, and tokens to read-only administrators. "
        "Upgrade to PAN-OS 10.2.8, PAN-OS 11.0.4, or later versions, and revoke all secrets "
        "configured in server profiles after upgrading. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-5916"
    )
