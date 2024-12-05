from comfy import high

@high(
    name='rule_cve202442505',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_papi_config='show configuration | include papi'
    ),
)
def rule_cve202442505(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42505 vulnerability in ArubaOS devices.
    The vulnerability allows unauthenticated remote attackers to execute arbitrary code through
    command injection in the PAPI protocol (UDP port 8211), which could lead to complete
    system compromise with privileged user access.
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
        '8.9.0.0', '8.8.0.0', '8.7.0.0', '8.6.0.0',
        '8.5.0.0', '8.4.0.0', '8.3.0.0', '8.2.0.0',
        '8.1.0.0', '8.0.0.0', '7.4.0.0', '6.5.4.0',
        '6.5.3.0', '6.5.2.0', '6.5.1.0', '6.5.0.0',
        '6.4.4.0', '6.4.3.0', '6.4.2.0', '6.4.1.0',
        '6.4.0.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if PAPI protocol is enabled
    papi_config = commands.show_papi_config
    papi_enabled = 'papi enable' in papi_config

    # Assert that the device is not vulnerable
    assert not papi_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42505. "
        "The device is running a vulnerable version with PAPI protocol enabled, "
        "which makes it susceptible to unauthenticated remote code execution attacks "
        "that could lead to complete system compromise with privileged access."
    )
