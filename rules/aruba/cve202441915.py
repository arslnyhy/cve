from comfy import high

@high(
    name='rule_cve202441915',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_web_server='show configuration | include web-server'
    ),
)
def rule_cve202441915(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-41915 vulnerability in Aruba ClearPass Policy Manager devices.
    The vulnerability allows authenticated remote attackers to conduct SQL injection attacks through
    the web-based management interface, which could lead to complete compromise of the ClearPass
    Policy Manager cluster through database manipulation.
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

    # Check if web management interface is enabled
    web_config = commands.show_web_server
    web_enabled = 'web-server enable' in web_config

    # Assert that the device is not vulnerable
    assert not web_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-41915. "
        "The device is running a vulnerable version with web management interface enabled, "
        "which makes it susceptible to authenticated SQL injection attacks "
        "that could lead to complete compromise of the ClearPass Policy Manager cluster."
    )
