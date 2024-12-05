from comfy import high

@high(
    name='rule_cve202442508',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_sensitive_config='show configuration | include sensitive'
    ),
)
def rule_cve202442508(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42508 vulnerability in ArubaOS devices.
    The vulnerability allows authenticated users to access sensitive information through
    improper access controls, which could lead to unauthorized disclosure of system data
    and configuration details.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions based on CVE data
    vulnerable_versions = [
        # 10.6.x versions
        '10.6.0.2', '10.6.0.1', '10.6.0.0',
        # 10.5.x and below
        '10.5.0.0', '10.4.1.13', '10.4.1.12', '10.4.1.11',
        '10.4.1.10', '10.4.1.9', '10.4.1.8', '10.4.1.7',
        '10.4.1.6', '10.4.1.5', '10.4.1.4', '10.4.1.3',
        '10.4.1.2', '10.4.1.1', '10.4.1.0', '10.4.0.0',
        '10.3.0.0', '10.2.0.0', '10.1.0.0', '10.0.0.0',
        # 8.12.x versions
        '8.12.0.1', '8.12.0.0',
        # 8.11.x versions
        '8.11.0.0',
        # 8.10.x versions
        '8.10.0.13', '8.10.0.12', '8.10.0.11', '8.10.0.10',
        '8.10.0.9', '8.10.0.8', '8.10.0.7', '8.10.0.6',
        '8.10.0.5', '8.10.0.4', '8.10.0.3', '8.10.0.2',
        '8.10.0.1', '8.10.0.0',
        # 8.9.x and below
        '8.9.0.0', '6.5.4.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if sensitive information access is enabled
    sensitive_config = commands.show_sensitive_config
    sensitive_access_enabled = 'sensitive access enable' in sensitive_config

    # Assert that the device is not vulnerable
    assert not sensitive_access_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42508. "
        "The device is running a vulnerable version with sensitive information access enabled, "
        "which makes it susceptible to unauthorized information disclosure "
        "that could expose system data and configuration details."
    )
