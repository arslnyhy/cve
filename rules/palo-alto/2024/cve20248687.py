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
    # Extract system info
    system_info = commands.show_system_info
    
    def is_version_affected(device_version: str, versions: list) -> bool:
        """
        Check if a device version is affected by comparing it against version ranges.
        
        Args:
            device_version: Device version string to check
            versions: List of dicts containing version ranges with 'version' and 'lessThan' keys
        
        Returns:
            bool: True if the version is affected, False otherwise
        """
        # Assuming normalized_cve_version is a separate function that normalizes version strings
        device_norm = normalized_cve_version(device_version)
        
        for version_range in versions:
            base_version = normalized_cve_version(version_range['version'])
            cap_version = normalized_cve_version(version_range['lessThan'])
            
            if base_version <= device_norm < cap_version:
                return True
                
        return False

    # Extract version information
    version = commands.show_system_info
    
    # Define version ranges for vulnerable versions
    vulnerable_version_ranges = [
        {'version': '8.1.0', 'lessThan': '8.1.25'},
        {'version': '9.0.0', 'lessThan': '9.0.17'},
        {'version': '9.1.0', 'lessThan': '9.1.16'},
        {'version': '10.0.0', 'lessThan': '10.0.12'},
        {'version': '10.1.0', 'lessThan': '10.1.9'},
        {'version': '10.2.0', 'lessThan': '10.2.4'},
        {'version': '11.0.0', 'lessThan': '11.0.1'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
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
