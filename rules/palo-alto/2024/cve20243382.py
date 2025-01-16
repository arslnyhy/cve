from comfy import high


@high(
    name='rule_cve20243382',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match "ssl-forward-proxy"'
    ),
)
def rule_cve20243382(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3382 in PAN-OS configurations.
    The vulnerability is a memory leak that enables an attacker to send a burst of crafted packets 
    through the firewall that eventually prevents the firewall from processing traffic. This issue 
    applies only to PA-5400 Series devices with SSL Forward Proxy enabled.
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
        {'version': '10.2.0', 'lessThan': '10.2.7-h3'},
        {'version': '11.0.0', 'lessThan': '11.0.4'},
        {'version': '11.1.0', 'lessThan': '11.1.2'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SSL Forward Proxy/Decryption is enabled
    config = commands.show_running_config
    if 'ssl-forward-proxy' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3382. "
        "The device is running a vulnerable version with SSL Forward Proxy enabled, making it susceptible "
        "to a memory leak that could prevent traffic processing through crafted packets. "
        "Upgrade to a fixed version: 10.2.7-h3+, 11.0.4+, 11.1.2+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3382"
    )
