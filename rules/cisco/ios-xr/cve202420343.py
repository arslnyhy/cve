from comfy import medium

@medium(
    name='rule_cve202420343',
    platform=['cisco_xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202420343(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific vulnerability (CVE-2024-20343)
    in Cisco IOS XR Software. The vulnerability allows an authenticated, local
    attacker to read any file in the file system of the underlying Linux operating
    system due to incorrect validation of CLI command arguments.

    The test will verify if the device is running a vulnerable version of Cisco IOS XR
    and will assert a failure if it is. The rule uses the 'show version' command to
    determine the software version of the device.
    """

    # Extract the version information from the 'show version' command output
    version_output = commands.show_version

    # List of vulnerable versions
    vulnerable_versions = [
        '7.10', '7.11', '24.1'
    ]

    # Check if the device's software version is in the list of vulnerable versions
    for version in vulnerable_versions:
        if version in version_output:
            # If a vulnerable version is found, assert failure with a message
            assert False, (
                f"Device {device.name} is running a vulnerable version of Cisco IOS XR "
                f"Software ({version}). It is affected by CVE-2024-20343. "
                "Please upgrade to a fixed release."
                "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-shellutil-HCb278wD"
            )

    # If no vulnerable version is found, the test passes
