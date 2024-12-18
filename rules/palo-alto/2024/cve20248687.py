from comfy import high


@high(
    name='rule_cve20248687',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match passcode'
    ),
)
def rule_cve20248687(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-8687 in PAN-OS devices.
    The vulnerability allows GlobalProtect end users to learn both the configured GlobalProtect 
    uninstall password and the configured disable/disconnect passcode, enabling unauthorized 
    uninstallation or disconnection of the GlobalProtect app.
    
    Fixed versions:
    - PAN-OS 8.1.25 and later
    - PAN-OS 9.0.17 and later
    - PAN-OS 9.1.16 and later
    - PAN-OS 10.0.12 and later
    - PAN-OS 10.1.9 and later
    - PAN-OS 10.2.4 and later
    - PAN-OS 11.0.1 and later
    """
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 8.1.', 'sw-version: 9.0.', 'sw-version: 9.1.',
                         'sw-version: 10.0.', 'sw-version: 10.1.', 'sw-version: 10.2.',
                         'sw-version: 11.0.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if GlobalProtect portal is configured with vulnerable settings
    config = commands.show_running_config
    if 'passcode' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-8687. "
        "The device is running a vulnerable version and has GlobalProtect portal configured "
        "with vulnerable password/passcode settings that could expose sensitive information. "
        "Upgrade to a fixed version: 8.1.25+, 9.0.17+, 9.1.16+, 10.0.12+, 10.1.9+, 10.2.4+, or 11.0.1+. "
        "As a workaround, change 'Allow User to Disable/Disconnect GlobalProtect App' to 'Allow with Ticket' "
        "and 'Allow User to Uninstall GlobalProtect App' to 'Disallow'. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-8687"
    )
