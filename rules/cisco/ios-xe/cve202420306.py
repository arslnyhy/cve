@medium(
    name='rule_cve202420306',
    platform=['cisco_xe'],
    commands=dict(show_version='show version', show_running_config='show running-config'),
)
def rule_cve202420306(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability (CVE-2024-20306) in Cisco IOS XE Software.
    The vulnerability allows an authenticated, local attacker to execute arbitrary commands as root
    due to insufficient input validation in the UTD configuration CLI.
    """

    # Extract the version information from the 'show version' command output
    version_output = commands.show_version
    # Check if the device is running a vulnerable version of Cisco IOS XE Software
    # (In a real scenario, you would compare the version against a list of known vulnerable versions)
    if 'Cisco IOS-XE Software' in version_output:
        # Check if the 'utd engine standard unified-policy' command is present in the configuration
        if 'utd engine standard unified-policy' in configuration:
            # If both conditions are met, the device is vulnerable
            # This assertion will fail the test, indicating a vulnerability
            assert False, f"Device {device.name} is vulnerable to CVE-2024-20306"
            "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-utd-cmd-JbL8KvHT"
