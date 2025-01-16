from comfy import high


@high(
    name='rule_cve20243383',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match "cloud-identity-engine"'
    ),
)
def rule_cve20243383(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3383 in PAN-OS configurations.
    The vulnerability in how PAN-OS software processes data received from Cloud Identity Engine (CIE) agents 
    enables modification of User-ID groups. This impacts user access to network resources where users may be 
    inappropriately denied or allowed access to resources based on existing Security Policy rules.
    """
    # Extract system info
    version_output = commands.show_system_info
    
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
        {'version': '10.1.0', 'lessThan': '10.1.11'},
        {'version': '10.2.0', 'lessThan': '10.2.5'},
        {'version': '11.0.0', 'lessThan': '11.0.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if Cloud Identity Engine (CIE) is enabled
    config = commands.show_running_config
    if 'cloud-identity-engine' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3383. "
        "The device is running a vulnerable version with Cloud Identity Engine (CIE) enabled, making it susceptible "
        "to unauthorized modification of User-ID groups which could impact access control. "
        "Upgrade to a fixed version: PAN-OS 10.1.11+, 10.2.5+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3383"
    )
