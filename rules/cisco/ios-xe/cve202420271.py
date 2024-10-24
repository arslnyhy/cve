from comfy import high

@high(
    name='rule_cve202420271',
    platform=['cisco_wlc', 'cisco_xe'],
    commands=dict(show_version='show version'),
)
def rule_cve202420271(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20271 vulnerability in Cisco Access Points.
    The vulnerability allows an unauthenticated, remote attacker to cause a denial of service (DoS) condition.
    It affects specific software versions of Cisco APs.
    """

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        '8.9', '8.10', '17.2', '17.4', '17.5', '17.7', '17.8', '17.10', '17.11', '10.8.1', '10.5.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable software version. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20271. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-dos-h9TGGX6W"
    )
