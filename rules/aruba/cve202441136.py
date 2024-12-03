from comfy import high

@high(
    name='rule_cve202441136',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_cli_config='show configuration | include cli'
    ),
)
def rule_cve202441136(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-41136 vulnerability in Aruba EdgeConnect SD-WAN devices.
    The vulnerability allows authenticated remote users to execute arbitrary commands as root
    through the Command Line Interface, which could lead to complete system compromise.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # 9.3.x versions
        '9.3.3.0', '9.3.2.', '9.3.1.', '9.3.0.',
        # 9.2.x versions
        '9.2.9.0', '9.2.8.', '9.2.7.', '9.2.6.', '9.2.5.', '9.2.4.',
        '9.2.3.', '9.2.2.', '9.2.1.', '9.2.0.',
        # 9.1.x versions
        '9.1.11.0', '9.1.10.', '9.1.9.', '9.1.8.', '9.1.7.', '9.1.6.',
        '9.1.5.', '9.1.4.', '9.1.3.', '9.1.2.', '9.1.1.', '9.1.0.',
        # 9.0.x versions (all affected)
        '9.0.',
        # 8.x versions (all affected)
        '8.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if CLI access is enabled
    cli_config = commands.show_cli_config
    cli_enabled = 'cli enable' in cli_config

    # Assert that the device is not vulnerable
    assert not cli_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-41136. "
        "The device is running a vulnerable version with CLI access enabled, "
        "which makes it susceptible to authenticated command injection attacks "
        "that could lead to complete system compromise."
    )
