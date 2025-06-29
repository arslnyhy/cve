from comfy import high


@high(
    name='rule_cve20240011',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running'
    ),
)
def rule_cve20240011(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0011 in PAN-OS devices.
    The vulnerability is a reflected XSS in the Captive Portal feature that could allow
    execution of malicious JavaScript if a user clicks on a malicious link, enabling phishing
    attacks that could lead to credential theft.
    
    Fixed versions:
    - PAN-OS 8.1.24 and later
    - PAN-OS 9.0.17 and later
    - PAN-OS 9.1.13 and later
    - PAN-OS 10.0.11 and later
    - PAN-OS 10.1.3 and later
    """
    # Extract version information
    version = commands.show_system_info
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '8.1.0', 'lessThan': '8.1.24'},
        {'version': '9.0.0', 'lessThan': '9.0.17'},
        {'version': '9.1.0', 'lessThan': '9.1.13'},
        {'version': '10.0.0', 'lessThan': '10.0.11'},
        {'version': '10.1.0', 'lessThan': '10.1.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if Captive Portal is enabled
    config = commands.show_running_config
    if 'captive-portal' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0011. "
        "The device is running a vulnerable version and has Captive Portal enabled, "
        "which makes it susceptible to reflected XSS attacks that could lead to credential theft. "
        "Upgrade to a fixed version: 8.1.24+, 9.0.17+, 9.1.13+, 10.0.11+, or 10.1.3+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0011"
    )
