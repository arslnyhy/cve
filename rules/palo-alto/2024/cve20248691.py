from comfy import high


@high(
    name='rule_cve20248691',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20248691(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-8691 in PAN-OS devices.
    The vulnerability allows a malicious authenticated GlobalProtect user to impersonate another 
    GlobalProtect user, causing the impersonated user to be disconnected and hiding the attacker's 
    identity in PAN-OS logs.
    
    Fixed versions:
    - PAN-OS 9.1.17 and later
    - PAN-OS 10.1.11 and later
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
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.1.0', 'lessThan': '10.1.11'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if GlobalProtect portal is enabled
    config = commands.show_global_protect
    if ('Gateway' not in config and 'iamportal' not in system_info):
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-8691. "
        "The device is running a vulnerable version and has GlobalProtect portal enabled, "
        "which could allow authenticated users to impersonate other users. "
        "Upgrade to a fixed version: 9.1.17+, 10.1.11+, or 10.2.0+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-8691"
    )
