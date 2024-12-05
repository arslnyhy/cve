from comfy import high

@high(
    name='rule_cve202425615',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_spectrum_config='show configuration | include spectrum'
    ),
)
def rule_cve202425615(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-25615 vulnerability in ArubaOS Wi-Fi Controllers and Campus/Remote Access Points.
    The vulnerability allows an unauthenticated attacker to cause a denial of service (DoS) condition through
    the Spectrum service accessed via the PAPI protocol.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # 10.5.x.x versions
        '10.5.0.1', '10.5.0.0',
        # 10.4.x.x versions
        '10.4.0.3', '10.4.0.2', '10.4.0.1', '10.4.0.0',
        # 10.3.x.x and below
        '10.3.',
        # 8.11.x.x versions
        '8.11.2.0', '8.11.1.', '8.11.0.',
        # 8.10.x.x versions
        '8.10.0.9', '8.10.0.8', '8.10.0.7', '8.10.0.6',
        '8.10.0.5', '8.10.0.4', '8.10.0.3', '8.10.0.2',
        '8.10.0.1', '8.10.0.0',
        # 8.9.x.x and below
        '8.9.', '8.8.', '8.7.', '8.6.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Spectrum service is enabled
    spectrum_config = commands.show_spectrum_config
    spectrum_enabled = 'spectrum enabled' in spectrum_config

    # Assert that the device is not vulnerable
    assert not spectrum_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-25615. "
        "The device is running a vulnerable version with Spectrum service enabled, "
        "which makes it susceptible to unauthenticated DoS attacks via PAPI protocol. "
        "For more information, see https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2024-002.txt"
    )
