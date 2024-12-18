from comfy import high


@high(
    name='rule_cve20248688',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20248688(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-8688 in PAN-OS devices.
    The vulnerability allows authenticated administrators (including read-only administrators) 
    with CLI access to read arbitrary files on the firewall due to improper neutralization 
    of matching symbols in the CLI interface.
    
    Fixed versions:
    - PAN-OS 9.1.15 and later
    - PAN-OS 10.0.10 and later
    - PAN-OS 10.1.1 and later
    - PAN-OS 10.2.0 and later
    """
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 9.1.', 'sw-version: 10.0.', 'sw-version: 10.1.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-8688. "
        "The device is running a vulnerable version which allows authenticated administrators "
        "to read arbitrary files on the firewall through the CLI due to improper symbol handling. "
        "Upgrade to a fixed version: 9.1.15+, 10.0.10+, 10.1.1+, or 10.2.0+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-8688"
    )
