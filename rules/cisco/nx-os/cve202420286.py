@medium(
    name='rule_cve202420284',
    platform=['cisco_nxos'],
    commands=dict(show_version='show version'),
)
def rule_cve202420284(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerable Cisco NX-OS software version
    that is susceptible to CVE-2024-20284. This CVE describes a vulnerability in the
    Python interpreter of Cisco NX-OS Software, allowing an authenticated, low-privileged,
    local attacker to escape the Python sandbox and gain unauthorized access to the
    underlying operating system.

    The vulnerability is due to insufficient validation of user-supplied input, which
    can be exploited by manipulating specific functions within the Python interpreter.
    """

    # Extract the version information from the 'show version' command output
    version_output = commands.show_version

    # Check if the device is running a vulnerable version
    # This is a simplified check; in a real scenario, you would parse the version
    # and compare it against known vulnerable versions.
    vulnerable_versions = ['9.3(13)']  # Example of a vulnerable version

    # Parse the version from the command output
    # This is a placeholder for actual parsing logic
    for line in version_output.splitlines():
        if 'NX-OS' in line:
            # Extract the version number from the line
            # Assuming the version number is the last word in the line
            current_version = line.split()[-1]
            break
    else:
        # If no version line is found, raise an error
        raise AssertionError("Unable to determine NX-OS version from output.")

    # Assert that the current version is not in the list of vulnerable versions
    assert current_version not in vulnerable_versions, (
        f"Device {device.name} is running a vulnerable NX-OS version: {current_version}. "
        "Please upgrade to a fixed version to mitigate CVE-2024-20284."
        "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-psbe-ce-YvbTn5du"
    )
