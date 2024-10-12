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

    # Extract the software version from the command output
    show_version_output = commands.show_version
    # This is a placeholder for extracting the version; adjust the regex based on actual output format
    import re
    version_match = re.search(r'Version (\d+\.\d+\.\d+)', show_version_output.source)

    if version_match:
        software_version = version_match.group(1)
        # Define a list of vulnerable versions based on the advisory
        vulnerable_versions = [
            '8.9', '8.10', '17.2', '17.3', '17.4', '17.5', '17.7', '17.8', '17.10', '17.11'
        ]

        # Check if the current software version is in the list of vulnerable versions
        if any(software_version.startswith(v) for v in vulnerable_versions):
            # If the version is vulnerable, the test fails
            assert False, f"Device {device.name} is running a vulnerable software version: {software_version}. Please upgrade to a fixed release."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-secureboot-bypass-zT5vJkSD"
    else:
        # If the version cannot be determined, raise an error
        assert False, "Unable to determine the software version from the device. Please check the command output format."
