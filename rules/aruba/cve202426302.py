from comfy import high

@high(
    name='rule_cve202426302',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_web_interface='show configuration | include web-interface'
    ),
)
def rule_cve202426302(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-26302 vulnerability in Aruba ClearPass Policy Manager.
    The vulnerability allows authenticated users with low privileges to access sensitive information
    through the web-based management interface, which could lead to further network access.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # 6.12.x versions
        '6.12.0',
        # 6.11.x versions and below
        '6.11.6', '6.11.5', '6.11.4', '6.11.3', '6.11.2', '6.11.1', '6.11.0',
        # 6.10.x versions
        '6.10.8', '6.10.7', '6.10.6', '6.10.5', '6.10.4', '6.10.3', '6.10.2', '6.10.1', '6.10.0',
        # 6.9.x versions and below
        '6.9.13', '6.9.12', '6.9.11', '6.9.10', '6.9.9', '6.9.8', '6.9.7', '6.9.6',
        '6.9.5', '6.9.4', '6.9.3', '6.9.2', '6.9.1', '6.9.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if web interface is enabled
    web_interface = commands.show_web_interface
    web_enabled = 'web-interface enabled' in web_interface

    # Assert that the device is not vulnerable
    assert not web_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-26302. "
        "The device is running a vulnerable version with web interface enabled, "
        "which allows authenticated users with low privileges to access sensitive information. "
        "For more information, see https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2024-001.txt"
    )
