from comfy import high


@high(
    name='rule_cve20240009',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20240009(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0009 in PAN-OS devices.
    The vulnerability allows a malicious user with stolen credentials to establish a VPN connection
    from an unauthorized IP address when GlobalProtect gateway is enabled.
    
    Fixed versions:
    - PAN-OS 10.2.4 and later
    - PAN-OS 11.0.1 and later
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
        {'version': '10.2.0', 'lessThan': '10.2.4'},
        {'version': '11.0.0', 'lessThan': '11.0.1'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if GlobalProtect gateway is enabled
    config = commands.show_global_protect
    if 'GlobalProtect' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0009. "
        "The device is running a vulnerable version and has GlobalProtect gateway enabled, "
        "which could allow unauthorized VPN connections from malicious users with stolen credentials. "
        "Upgrade to a fixed version: 10.2.4+ or 11.0.1+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0009"
    )
