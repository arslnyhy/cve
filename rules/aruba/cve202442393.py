from comfy import high

@high(
    name='rule_cve202442393',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_soft_ap='show configuration | include soft-ap'
    ),
)
def rule_cve202442393(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42393 vulnerability in Aruba InstantOS and Access Points.
    The vulnerability allows unauthenticated remote attackers to execute arbitrary commands through
    the Soft AP Daemon Service via the PAPI protocol, which could lead to complete system compromise.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions based on CVE data
    vulnerable_versions = [
        # 8.12.x versions
        '8.12.0.1', '8.12.0.0',
        # 8.10.x versions
        '8.10.0.12', '8.10.0.11', '8.10.0.10', '8.10.0.9', '8.10.0.8',
        '8.10.0.7', '8.10.0.6', '8.10.0.5', '8.10.0.4', '8.10.0.3',
        '8.10.0.2', '8.10.0.1', '8.10.0.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Soft AP Daemon Service is enabled
    soft_ap_config = commands.show_soft_ap
    soft_ap_enabled = 'soft-ap enable' in soft_ap_config

    # Assert that the device is not vulnerable
    assert not soft_ap_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42393. "
        "The device is running a vulnerable version with Soft AP Daemon Service enabled, "
        "which makes it susceptible to unauthenticated remote code execution attacks "
        "that could lead to complete system compromise."
    )
