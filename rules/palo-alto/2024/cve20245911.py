from comfy import high


@high(
    name='rule_cve20245911',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20245911(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5911 in PAN-OS Panorama appliances.
    The vulnerability allows an authenticated read-write administrator with web interface access
    to upload arbitrary files that could disrupt system processes and crash the Panorama.
    Repeated attacks can cause the Panorama to enter maintenance mode.
    
    Fixed versions:
    - PAN-OS 10.1.9 and later
    - PAN-OS 10.2.4 and later
    - PAN-OS 11.0.0 and later
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
        {'version': '10.1.0', 'lessThan': '10.1.9'},
        {'version': '10.2.0', 'lessThan': '10.2.4'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-5911. "
        "The Panorama appliance is running a vulnerable version which allows authenticated "
        "read-write administrators to upload arbitrary files that could crash the system. "
        "Upgrade to a fixed version: 10.1.9+, 10.2.4+, or 11.0.0+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-5911"
    )
