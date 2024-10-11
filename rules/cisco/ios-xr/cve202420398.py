@high(
    name='rule_cisco_iosxr_privilege_escalation',
    platform=['cisco_xr'],
    commands=dict(show_version='show version'),
)
def rule_cisco_iosxr_privilege_escalation(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific vulnerability in Cisco IOS XR Software.
    The vulnerability allows an authenticated, local attacker to escalate privileges to root
    due to insufficient validation of user arguments in CLI commands.
    """

    # Extract the software version from the 'show version' command output
    show_version_output = commands.show_version
    # Here, we assume that the version string can be found in the output.
    # In practice, you would need to parse the output correctly to extract the version.
    version_line = next((line for line in show_version_output.splitlines() if "Version" in line), None)
    
    if version_line:
        # Extract the version number from the line
        # This is a simplified example; actual parsing may require regex or more complex logic
        version_number = version_line.split("Version")[-1].strip()

        # List of vulnerable versions
        vulnerable_versions = [
            "7.11", "24.1", # Add more vulnerable versions if necessary
        ]

        # Check if the current version is in the list of vulnerable versions
        if any(version_number.startswith(v) for v in vulnerable_versions):
            # If the device is running a vulnerable version, the test fails
            assert False, (
                f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software: {version_number}. "
                "Please upgrade to a fixed version to mitigate CVE-2024-20398."
                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-priv-esc-CrG5vhCq"
            )
    else:
        # If we can't determine the version, we should raise a warning or handle it appropriately
        assert False, (
            f"Could not determine the software version for device {device.name}. "
            "Please verify the device configuration manually."
        )
