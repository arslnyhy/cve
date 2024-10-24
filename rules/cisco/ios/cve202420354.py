from comfy import medium


@medium(
    name='rule_cve202420354',
    platform=['cisco_ios'],
    commands=dict(show_version='show version'),
)
def rule_cve202420354(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20354 vulnerability in Cisco Aironet APs.
    The vulnerability is due to improper handling of malformed wireless frames,
    which can lead to a denial of service (DoS) condition.
    """

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for Cisco Aironet APs
    # Checkout documentaton to see fixed versions
    # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-airo-ap-dos-PPPtcVW
    vulnerable_versions = [
        '8.5.171.0',
        '8.10.130.0',
        '16.12.4a',
        '17.3',
        '17.6',
        '17.9',
        '17.12',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco Aironet AP Software. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20354."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-airo-ap-dos-PPPtcVW"
    )
