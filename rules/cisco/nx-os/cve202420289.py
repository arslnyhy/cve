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

    # Define a list of vulnerable versions
    vulnerable_versions = [
        "7.0(3)I7(5)",
    ]
    
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Check if the device's software version is in the list of vulnerable versions
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco NX-OS: {version_output}. "
        "Please upgrade to a fixed version to mitigate CVE-2024-20289."
        "For more information, see: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmdinj-Lq6jsZhH"
    )
