from comfy import high


@high(
    name='rule_cve20240010',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20240010(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0010 in PAN-OS devices.
    The vulnerability is a reflected XSS in the GlobalProtect portal feature that could allow
    execution of malicious JavaScript if a user clicks on a malicious link, enabling phishing
    attacks that could lead to credential theft.
    
    Fixed versions:
    - PAN-OS 9.0.17-h4 and later
    - PAN-OS 9.1.17 and later
    - PAN-OS 10.1.11-h1 and later
    - PAN-OS 10.1.12 and later
    """
    # Extract version information
    version = commands.show_system_info
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '9.0.0', 'lessThan': '9.0.17-h4'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.1.0', 'lessThan': '10.1.11-h1'},
        {'version': '10.1.11-h1', 'lessThan': '10.1.12'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if GlobalProtect portal is enabled
    config = commands.show_global_protect
    if 'iamportal' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0010. "
        "The device is running a vulnerable version and has GlobalProtect portal enabled, "
        "which makes it susceptible to reflected XSS attacks that could lead to credential theft. "
        "Upgrade to a fixed version: 9.0.17-h4+, 9.1.17+, 10.1.11-h1+, or 10.1.12+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0010"
    )
