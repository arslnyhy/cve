from comfy import high

@high(
    name='rule_cve202420398',
    platform=['cisco_xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202420398(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker to escalate privileges to root
    due to insufficient validation of user arguments in CLI commands.
    """

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        '7.11', '24.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20398. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-priv-esc-CrG5vhCq"
    )
