from comfy import high

@high(
    name='rule_cve202431471',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_papi='show configuration | include papi'
    ),
)
def rule_cve202431471(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-31471 vulnerability in Aruba InstantOS and ArubaOS devices.
    The vulnerability allows unauthenticated remote code execution through command injection
    in the Central Communications service via PAPI UDP port (8211).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # 10.5.x versions
        '10.5.1.0', '10.5.0.0',
        # 10.4.x versions
        '10.4.1.0', '10.4.0.0',
        # 10.3.x and below
        '10.3.',
        # 8.11.x versions
        '8.11.2.1', '8.11.1.', '8.11.0.',
        # 8.10.x versions
        '8.10.0.10', '8.10.0.9', '8.10.0.8', '8.10.0.7', '8.10.0.6',
        '8.10.0.5', '8.10.0.4', '8.10.0.3', '8.10.0.2', '8.10.0.1', '8.10.0.0',
        # 8.6.x versions
        '8.6.0.23', '8.6.0.22', '8.6.0.21', '8.6.0.20', '8.6.0.19',
        '8.6.0.18', '8.6.0.17', '8.6.0.16', '8.6.0.15', '8.6.0.14'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if PAPI service is enabled
    papi_config = commands.show_papi
    papi_enabled = 'papi enabled' in papi_config

    # Assert that the device is not vulnerable
    assert not papi_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-31471. "
        "The device is running a vulnerable version with PAPI service enabled, "
        "which makes it susceptible to unauthenticated remote code execution through command injection."
    )
