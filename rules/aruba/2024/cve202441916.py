from comfy import high

@high(
    name='rule_cve202441916',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_admin_access='show configuration | include admin'
    ),
)
def rule_cve202441916(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-41916 vulnerability in Aruba ClearPass Policy Manager devices.
    The vulnerability allows authenticated administrators to access sensitive information in cleartext,
    which could be used to gain further access to network services supported by ClearPass Policy Manager.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # 6.12.x versions
        '6.12.1', '6.12.0',
        # 6.11.x versions
        '6.11.8', '6.11.7', '6.11.6', '6.11.5', '6.11.4',
        '6.11.3', '6.11.2', '6.11.1', '6.11.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if administrative access is enabled
    admin_config = commands.show_admin_access
    admin_enabled = 'admin enable' in admin_config

    # Assert that the device is not vulnerable
    assert not admin_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-41916. "
        "The device is running a vulnerable version with administrative access enabled, "
        "which makes it susceptible to sensitive information disclosure in cleartext "
        "that could lead to further network service compromise."
    )
