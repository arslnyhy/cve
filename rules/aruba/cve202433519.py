from comfy import high

@high(
    name='rule_cve202433519',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_web_server='show configuration | include web-server'
    ),
)
def rule_cve202433519(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-33519 vulnerability in Aruba EdgeConnect SD-WAN devices.
    The vulnerability allows authenticated remote attackers to conduct server-side prototype
    pollution attacks through the web-based management interface, which could lead to arbitrary
    command execution and complete system compromise.
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

    # Check if web management interface is enabled
    web_config = commands.show_web_server
    web_enabled = 'web-server enable' in web_config

    # Assert that the device is not vulnerable
    assert not web_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-33519. "
        "The device is running a vulnerable version with web management interface enabled, "
        "which makes it susceptible to authenticated server-side prototype pollution attacks "
        "that could lead to arbitrary command execution."
    )
