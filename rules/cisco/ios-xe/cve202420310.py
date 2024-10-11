@medium(
    name='rule_cucm_imps_xss',
    platform=['cisco_xe'],  # Assuming the platform is Cisco IOS for demonstration
    commands=dict(show_version='show version'),  # Example command to gather device info
)
def rule_cucm_imps_xss(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerable version of Cisco Unified CM IM&P
    that is susceptible to a cross-site scripting (XSS) vulnerability identified by CVE-2024-20310.
    """

    # Extract the software version from the device configuration or command output
    # This is a placeholder for actual logic to determine the software version
    software_version = "12.5(1)"  # Example version for demonstration purposes

    # List of vulnerable versions
    vulnerable_versions = ['12.5(1)', '12.5(0)', '12.0(0)']  # Add more as needed

    # Check if the current software version is in the list of vulnerable versions
    if software_version in vulnerable_versions:
        # If the version is vulnerable, the test fails
        assert False, (
            f"Device {device.name} is running a vulnerable version of Cisco Unified CM IM&P: {software_version}. "
            "This version is susceptible to CVE-2024-20310. Please upgrade to a fixed release."
        )
    else:
        # If the version is not vulnerable, the test passes
        assert True, (
            f"Device {device.name} is running a non-vulnerable version of Cisco Unified CM IM&P: {software_version}."
            "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-imps-xss-quWkd9yF"
        )
