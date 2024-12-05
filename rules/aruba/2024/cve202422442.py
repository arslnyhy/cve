from comfy import high

@high(
    name='rule_cve202422442',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_service_config='show configuration | include service-processor'
    ),
)
def rule_cve202422442(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-22442 vulnerability in HPE 3PAR Service Processor.
    The vulnerability allows an unauthenticated remote attacker to bypass authentication,
    potentially leading to complete system compromise.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions (5.1.1 and below)
    vulnerable_versions = [
        # 5.1.x versions
        '5.1.1', '5.1.0',
        # 5.0.x and below
        '5.0.', '4.', '3.', '2.', '1.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if service processor is enabled
    service_config = commands.show_service_config
    service_enabled = 'service-processor enabled' in service_config

    # Assert that the device is not vulnerable
    assert not service_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-22442. "
        "The device is running a vulnerable version with service processor enabled, "
        "which makes it susceptible to remote authentication bypass attacks. "
        "For more information, see https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbst04663en_us"
    )
