from comfy import high

@high(
    name='rule_cve202422441',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_pals_config='show configuration | include pals'
    ),
)
def rule_cve202422441(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-22441 vulnerability in HPE Cray Parallel Application Launch Service (PALS).
    The vulnerability allows an attacker to bypass authentication controls, potentially leading to
    unauthorized access to the system.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions (1.3.2 and below)
    vulnerable_versions = [
        # 1.3.x versions
        '1.3.2', '1.3.1', '1.3.0',
        # 1.2.x and below
        '1.2.', '1.1.', '1.0.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if PALS service is enabled
    pals_config = commands.show_pals_config
    pals_enabled = 'pals service enabled' in pals_config

    # Assert that the device is not vulnerable
    assert not pals_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-22441. "
        "The device is running a vulnerable version with PALS service enabled, "
        "which makes it susceptible to authentication bypass attacks. "
        "For more information, see https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbcr04653en_us"
    )
