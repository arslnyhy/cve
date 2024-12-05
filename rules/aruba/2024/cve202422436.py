from comfy import high

@high(
    name='rule_cve202422436',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_agent_config='show configuration | include agent'
    ),
)
def rule_cve202422436(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-22436 vulnerability in HPE IceWall Agent products.
    The vulnerability allows an unauthenticated remote attacker to cause a denial of service
    through resource exhaustion in the agent service.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # IceWall SSO Agent versions
        '10.0',
        # IceWall Gen11 Agent versions
        '11.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if agent service is enabled
    agent_config = commands.show_agent_config
    agent_enabled = 'agent service enabled' in agent_config

    # Assert that the device is not vulnerable
    assert not agent_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-22436. "
        "The device is running a vulnerable version with agent service enabled, "
        "which makes it susceptible to remote denial of service attacks through resource exhaustion. "
        "For more information, see https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=hpesbmu04626en_us"
    )
