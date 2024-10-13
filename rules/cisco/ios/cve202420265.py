from comfy import high


@high(
    name='rule_cve202420265',
    platform=['cisco_ios'],
    commands=dict(show_version='show version'),
)
def rule_cve202420265(configuration, commands, device, devices):
    """
    This rule checks for the Cisco Access Point Software Secure Boot Bypass Vulnerability (CVE-2024-20265).
    The vulnerability allows an unauthenticated, physical attacker to bypass the Cisco Secure Boot functionality
    and load a tampered software image on an affected device.

    The test will verify if the device is running a software version that is known to be vulnerable.
    If the device is running a vulnerable version, the test will fail.
    """

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        '8.9', '8.10', '17.2', '17.3', '17.4', '17.5', '17.7', '17.8', '17.10', '17.11'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS Software. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20265. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-secureboot-bypass-zT5vJkSD"
    )
