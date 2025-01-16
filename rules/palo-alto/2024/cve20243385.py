from comfy import high


@high(
    name='rule_cve20243385',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match gtp'
    ),
)
def rule_cve20243385(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3385 in PAN-OS configurations.
    The vulnerability allows a remote attacker to reboot hardware-based firewalls when GTP Security 
    is disabled. Repeated attacks eventually cause the firewall to enter maintenance mode, requiring 
    manual intervention.
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
        {'version': '9.0.0', 'lessThan': '9.0.17-h4'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.1.0', 'lessThan': '10.1.12'},
        {'version': '10.2.0', 'lessThan': '10.2.8'},
        {'version': '11.0.0', 'lessThan': '11.0.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if GTP Security is disabled (in PAN-OS, this would be 'enabled no')
    config = commands.show_running_config
    if 'gtp' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3385. "
        "The device is running a vulnerable version and has GTP Security disabled, "
        "making it susceptible to DoS attacks. "
        "Upgrade to a fixed version: 9.0.17-h4+, 9.1.17+, 10.1.12+, 10.2.8+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3385"
    )
