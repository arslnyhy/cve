from comfy import high


@high(
    name='rule_cve20243388',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20243388(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3388 in PAN-OS configurations.
    The vulnerability in GlobalProtect Gateway allows an authenticated attacker to impersonate 
    another user and send network packets to internal assets when SSL VPN is enabled.
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
        {'version': '8.1.0', 'lessThan': '8.1.26'},
        {'version': '9.0.0', 'lessThan': '9.0.17-h4'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.1.0', 'lessThan': '10.1.11-h4'},
        {'version': '10.2.0', 'lessThan': '10.2.7-h3'},
        {'version': '11.0.0', 'lessThan': '11.0.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if GlobalProtect gateway is configured
    config = commands.show_global_protect
    if 'Gateway' not in config:
        return

    # Check if SSL VPN is enabled
    config = commands.show_running_config
    if ('ssl' not in config and 'tls' not in config):
        return
        
    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3388. "
        "The device is running a vulnerable version and has GlobalProtect gateway configured "
        "with SSL VPN enabled (either as fallback or primary mode), which could allow "
        "authenticated users to impersonate others and send packets to internal assets. "
        "Upgrade to a fixed version: 8.1.26+, 9.0.17-h4+, 9.1.17+, 10.1.11-h4+, 10.2.7-h3+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3388"
    )
