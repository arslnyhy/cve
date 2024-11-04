from comfy import medium

@medium(
    name='rule_cve202420289',
    platform=['cisco_nxos'],
    commands=dict(show_version='show version'),
)
def rule_cve202420289(configuration, commands, device, devices):
    """
    This rule checks for the presence of a known Cisco NX-OS Software vulnerability (CVE-2024-20289).
    The vulnerability allows an authenticated, low-privileged, local attacker to execute arbitrary commands
    on the underlying operating system of an affected device due to insufficient validation of arguments
    for a specific CLI command.
    
    The test checks if the device is running a vulnerable version of Cisco NX-OS Software.
    """

    # Extract the software version from the 'show version' command output
    version_output = commands.show_version

    # Define a list of vulnerable versions from the notepad
    vulnerable_versions = [
        # 9.3.x versions
        '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(5w)', '9.3(7)', '9.3(7k)',
        '9.3(7a)', '9.3(8)', '9.3(9)', '9.3(10)', '9.3(11)', '9.3(12)',
        # 10.1.x versions
        '10.1(1)', '10.1(2)', '10.1(2t)',
        # 10.2.x versions
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(2a)', '10.2(3)', '10.2(3t)',
        '10.2(3v)', '10.2(4)', '10.2(5)', '10.2(6)',
        # 10.3.x versions
        '10.3(1)', '10.3(2)', '10.3(3)', '10.3(3o)', '10.3(3p)', '10.3(3q)',
        '10.3(3r)', '10.3(3w)', '10.3(3x)', '10.3(4)', '10.3(4a)', '10.3(4g)',
        '10.3(99w)', '10.3(99x)',
        # 10.4.x versions
        '10.4(1)', '10.4(2)'
    ]
    
    # Check if the device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    assert not version_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco NX-OS. "
        "Please upgrade to a fixed version to mitigate CVE-2024-20289. "
        "For more information, see: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmdinj-Lq6jsZhH"
    )
