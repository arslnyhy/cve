from comfy import high


@high(
    name='rule_cve20248686',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20248686(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-8686 in PAN-OS devices.
    The vulnerability allows an authenticated administrator to bypass system restrictions 
    and run arbitrary commands as root on the firewall through command injection.
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
        {'version': '11.2.2', 'lessThan': '11.2.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-8686. "
        "The device is running PAN-OS 11.2.2 which contains a command injection vulnerability "
        "that could allow authenticated administrators to run arbitrary commands as root. "
        "Upgrade to PAN-OS 11.2.3 or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-8686"
    )
