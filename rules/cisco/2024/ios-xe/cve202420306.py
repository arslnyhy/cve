from comfy import medium

@medium(
    name='rule_cve202420306',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202420306(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability (CVE-2024-20306) in Cisco IOS XE Software.
    The vulnerability allows an authenticated, local attacker to execute arbitrary commands as root
    due to insufficient input validation in the UTD configuration CLI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW',
        # 17.12.x versions
        '17.12.1', '17.12.1w', '17.12.1a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the device is running Cisco IOS XE Software and has UTD configured
    running_config = commands.show_running_config

    # Check if the 'utd engine standard unified-policy' command is present in the configuration
    if 'utd engine standard unified-policy' in running_config:
        # If both conditions are met (vulnerable version and UTD enabled), the device is vulnerable
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2024-20306. "
            "The device is running a vulnerable version AND has UTD feature enabled. "
            "Please update the software or disable the UTD feature. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-utd-cmd-JbL8KvHT"
        )
