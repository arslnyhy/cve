@medium(
    name='rule_cve202420284',
    platform=['cisco_nxos'],
    commands=dict(show_version='show version'),
)
def rule_cve202420284(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2024-20284 vulnerability in Cisco NX-OS devices.
    The vulnerability allows an authenticated, low-privileged, local attacker to escape the Python
    sandbox and gain unauthorized access to the underlying operating system of the device.
    """

    # Extract the software version from the 'show version' command output
    show_version_output = commands.show_version
    # Here, we assume that the version string is present in the output
    # For simplicity, let's assume the version is extracted as a string like '9.3(13)'
    # In a real scenario, you might need to parse the output to extract the version number
    vulnerable_versions = ['9.3(13)']  # Add other vulnerable versions if known

    # Check if the current version is in the list of vulnerable versions
    is_vulnerable = any(version in show_version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the assertion fails, it indicates the device is vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco NX-OS software. "
        "Please upgrade to a fixed version to mitigate CVE-2024-20284."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-psbe-ce-YvbTn5du"
    )
