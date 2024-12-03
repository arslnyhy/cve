from comfy import high

@high(
    name='rule_cve202442395',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_cert_mgmt='show configuration | include certificate-mgmt'
    ),
)
def rule_cve202442395(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42395 vulnerability in Aruba InstantOS and Access Points.
    The vulnerability in the AP Certificate Management Service allows unauthenticated remote attackers
    to execute arbitrary commands through the PAPI protocol, which could lead to complete system compromise.
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

    # Check if Certificate Management Service is enabled
    cert_mgmt_config = commands.show_cert_mgmt
    cert_mgmt_enabled = 'certificate-mgmt enable' in cert_mgmt_config

    # Assert that the device is not vulnerable
    assert not cert_mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42395. "
        "The device is running a vulnerable version with Certificate Management Service enabled, "
        "which makes it susceptible to unauthenticated remote code execution attacks "
        "that could lead to complete system compromise via the PAPI protocol."
    )
