from comfy import high

@high(
    name='rule_cve20246206',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_container_config='show container config'
    ),
)
def rule_cve20246206(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-6206 vulnerability in HPE Athonet Mobile Core software.
    The vulnerability allows a threat actor to execute arbitrary commands with the privilege 
    of the underlying container through code injection, leading to complete system takeover.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions (1.23.4.2 and below)
    vulnerable_versions = [
        '1.23.4.2', '1.23.4.1', '1.23.4.0',
        '1.23.3.', '1.23.2.', '1.23.1.', '1.23.0.',
        '1.22.', '1.21.', '1.20.',
        '1.1.', '1.0.'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check container configuration for privileged access
    container_config = commands.show_container_config
    privileged_access = 'privileged: true' in container_config

    # Assert that the device is not vulnerable
    assert not privileged_access, (
        f"Device {device.name} is vulnerable to CVE-2024-6206. "
        "The device is running a vulnerable version with privileged container access, "
        "which makes it susceptible to code injection attacks leading to system takeover. "
        "For more information, see https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbgn04659en_us"
    )
