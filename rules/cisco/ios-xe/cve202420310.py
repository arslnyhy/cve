from comfy import medium

@medium(
    name='rule_cve202420310',
    platform=['cisco_xe'],
    commands=dict(show_version='show version'),
)
def rule_cve202420310(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerable version of Cisco Unified CM IM&P
    that is susceptible to a cross-site scripting (XSS) vulnerability identified by CVE-2024-20310.
    """

    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions
    vulnerable_versions = ['12.5(1)', '12.5(0)', '12.0(0)']  # Add more as needed

    # Check if the current device's software version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco Unified CM IM&P. "
        "This version is susceptible to CVE-2024-20310. Please upgrade to a fixed release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-imps-xss-quWkd9yF"
    )
