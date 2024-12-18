from comfy import high


@high(
    name='rule_cve20242433',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20242433(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-2433 in Panorama configurations.
    The vulnerability allows an authenticated read-only administrator to upload files using the web interface 
    and completely fill one of the disk partitions, which prevents the ability to log into the web interface 
    or to download PAN-OS, WildFire, and content images.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable versions
    vulnerable_versions = [
        'sw-version: 9.', 'sw-version: 10.', 'sw-version: 11.0'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if Panorama is enabled
    config = commands.show_system_info
    if 'model: PA' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-2433. "
        "The device is running a vulnerable version of Panorama that allows read-only administrators "
        "to upload files and fill disk partitions, preventing web interface access. "
        "Upgrade to a fixed version: 9.0.17-h4+, 9.1.18+, 10.1.12+, 10.2.11+, 11.0.4+, or 11.1+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-2433"
    )
