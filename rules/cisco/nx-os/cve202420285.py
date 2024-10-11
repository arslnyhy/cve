@medium(
    name='rule_cve202420284',
    platform=['cisco_nxos'],
    commands=dict(show_version='show version'),
)
def rule_cve202420284(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerable NX-OS version that is susceptible
    to the Python Sandbox Escape Vulnerabilities (CVE-2024-20284, CVE-2024-20285, CVE-2024-20286).
    The vulnerabilities allow an authenticated attacker to escape the Python sandbox
    and execute arbitrary commands on the device.
    """

    # Extract the version information from the 'show version' command output
    version_output = commands.show_version

    # List of known vulnerable versions for Cisco NX-OS
    vulnerable_versions = [
        '9.3(13)',  # Example version; replace with actual vulnerable versions if different
    ]

    # Check if the current device version is in the list of vulnerable versions
    is_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable NX-OS version. "
        "Please upgrade to a fixed version to mitigate CVE-2024-20284."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-psbe-ce-YvbTn5du"
    )
