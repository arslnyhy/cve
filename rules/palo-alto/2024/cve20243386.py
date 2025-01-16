from comfy import high


@high(
    name='rule_cve20243386',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match ssl-decrypt'
    ),
)
def rule_cve20243386(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3386 in PAN-OS configurations.
    The vulnerability is due to incorrect string comparison that prevents Predefined Decryption 
    Exclusions from functioning as intended, causing unintended traffic to be excluded from decryption.
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
        {'version': '9.0.0', 'lessThan': '9.0.17-h2'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.0.0', 'lessThan': '10.0.13'},
        {'version': '10.1.0', 'lessThan': '10.1.9-h3'},
        {'version': '10.2.0', 'lessThan': '10.2.4-h2'},
        {'version': '11.0.0', 'lessThan': '11.0.1-h2'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SSL decryption is configured with exclusions
    config = commands.show_running_config
    if 'ssl-decrypt' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3386. "
        "The device is running a vulnerable version and has SSL decryption enabled, "
        "which may cause traffic to be unintentionally excluded from decryption. "
        "Upgrade to a fixed version: 9.0.17-h2+, 9.1.17+, 10.0.13+, 10.1.9-h3+, 10.2.4-h2+, 11.0.1-h2+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3386"
    )
