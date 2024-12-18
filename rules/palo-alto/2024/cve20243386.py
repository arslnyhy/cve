from comfy import high


@high(
    name='rule_cve20243386',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match ssl-decrypt'
    ),
)
def rule_cve20243386(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3386 in PAN-OS configurations.
    The vulnerability is due to incorrect string comparison that prevents Predefined Decryption 
    Exclusions from functioning as intended, causing unintended traffic to be excluded from decryption.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 9.0.', 'sw-version: 9.1.', 'sw-version: 10.0.', 'sw-version: 10.1.', 'sw-version: 10.2.', 'sw-version: 11.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SSL decryption is configured with exclusions
    config = commands.show_running_config
    if 'ssl-decrypt' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3386. "
        "The device is running a vulnerable version and has SSL decryption enabled, "
        "which may cause traffic to be unintentionally excluded from decryption. "
        "Upgrade to a fixed version: 9.0.17-h2+, 9.1.17+, 10.0.13+, 10.1.9-h3+, 10.2.4-h2+, 11.0.1-h2+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3386"
    )
