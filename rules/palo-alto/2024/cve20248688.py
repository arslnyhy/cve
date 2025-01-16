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
        {'version': '9.1.0', 'lessThan': '9.1.15'},
        {'version': '10.0.0', 'lessThan': '10.0.10'},
        {'version': '10.1.0', 'lessThan': '10.1.1'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
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
