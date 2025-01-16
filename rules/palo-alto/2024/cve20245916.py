from comfy import high


@high(
    name='rule_cve20245916',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_server_profiles='show config running | match "server-profile"'
    ),
)
def rule_cve20245916(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5916 in PAN-OS devices.
    The vulnerability allows read-only administrators to access secrets, passwords, and tokens 
    configured in server profiles through the config log.
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
        {'version': '10.2.0', 'lessThan': '10.2.8'},
        {'version': '11.0.0', 'lessThan': '11.0.4'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if server profiles are configured
    config = commands.show_server_profiles
    has_server_profiles = 'server-profile' in config

    # Assert that the device is not vulnerable
    assert not has_server_profiles, (
        f"Device {device.name} is vulnerable to CVE-2024-5916. "
        "The device is running a vulnerable version AND has server profiles configured, "
        "which could expose secrets, passwords, and tokens to read-only administrators. "
        "Upgrade to PAN-OS 10.2.8, PAN-OS 11.0.4, or later versions, and revoke all secrets "
        "configured in server profiles after upgrading. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-5916"
    )
