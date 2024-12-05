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

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 6.5.x versions
        '6.5.1', '6.5.2', '6.5.3', '6.5.15', '6.5.92', '6.5.93',
        # 6.6.x versions
        '6.6.1', '6.6.2', '6.6.3', '6.6.4', '6.6.11', '6.6.12', '6.6.25',
        # 7.0.x versions
        '7.0.0', '7.0.1', '7.0.2', '7.0.11', '7.0.12', '7.0.14', '7.0.90',
        # 7.1.x versions
        '7.1.1', '7.1.2', '7.1.3', '7.1.15', '7.1.25',
        # 7.2.x versions
        '7.2.0', '7.2.1', '7.2.2', '7.2.12',
        # 7.3.x versions
        '7.3.1', '7.3.2', '7.3.3', '7.3.4', '7.3.5', '7.3.6', '7.3.15', '7.3.16', '7.3.27',
        # 7.4.x versions
        '7.4.1', '7.4.2', '7.4.15', '7.4.16',
        # 7.5.x versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5', '7.5.12', '7.5.52',
        # 7.6.x versions
        '7.6.1', '7.6.2', '7.6.15',
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2', '7.8.12', '7.8.22',
        # 7.9.x versions
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1', '7.10.2',
        # 7.11.x versions
        '7.11.1',
        # 24.x versions
        '24.1.1'
    ]

    # Check if the device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If a vulnerable version is found, assert failure with a message
    assert not version_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software. "
        "It is affected by CVE-2024-20343. Please upgrade to a fixed release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-shellutil-HCb278wD"
    )

