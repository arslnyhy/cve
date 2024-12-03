from comfy import high

@high(
    name='rule_cve20245486',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_config='show configuration | include clearpass'
    ),
)
def rule_cve20245486(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5486 vulnerability in HPE ClearPass Policy Manager.
    The vulnerability allows an attacker with administrative privileges to access sensitive
    information in cleartext format, which could be used to gain further access to network services.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions (6.12.1 and below, 6.11.8 and below)
    vulnerable_versions = [
        # 6.12.x versions
        '6.12.1', '6.12.0',
        # 6.11.x versions
        '6.11.8', '6.11.7', '6.11.6', '6.11.5', '6.11.4',
        '6.11.3', '6.11.2', '6.11.1', '6.11.0',
        # 6.10.x and below
        '6.10.', '6.9.', '6.8.', '6.7.', '6.6.',
        '6.5.', '6.4.', '6.3.', '6.2.', '6.1.', '6.0.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if ClearPass is configured with admin access
    config_output = commands.show_config
    admin_access = 'clearpass admin' in config_output

    # Assert that the device is not vulnerable
    assert not admin_access, (
        f"Device {device.name} is vulnerable to CVE-2024-5486. "
        "The device is running a vulnerable version with administrative access enabled, "
        "which makes it susceptible to sensitive information disclosure in cleartext format. "
        "For more information, see https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04675en_us"
    )
