from comfy import high


@high(
    name='rule_cve20243400',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20243400(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3400 in PAN-OS configurations.
    The vulnerability in GlobalProtect allows an unauthenticated attacker to execute arbitrary code 
    with root privileges through command injection via arbitrary file creation.
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
        {'version': '10.2.0', 'lessThan': '10.2.9-h1'},
        {'version': '11.0.0', 'lessThan': '11.0.4-h1'},
        {'version': '11.1.0', 'lessThan': '11.1.2-h3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    global_protect = commands.show_global_protect
    if 'Gateway' not in global_protect and 'iamportal' not in system_info:
        return

# Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3400. "
        "The device is running a vulnerable version and has GlobalProtect gateway or portal configured, "
        "which could allow unauthenticated attackers to execute arbitrary code with root privileges. "
        "This vulnerability is being actively exploited in the wild. "
        "Upgrade to a fixed version: 10.2.9-h1+, 11.0.4-h1+, 11.1.2-h3+, or later. "
        "Enable Threat Prevention with IDs 95187, 95189, and 95191 as a mitigation. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3400"
    )
