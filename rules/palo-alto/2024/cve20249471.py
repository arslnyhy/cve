from comfy import high


@high(
    name='rule_cve20249471',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running'
    ),
)
def rule_cve20249471(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-9471 in PAN-OS devices.
    The vulnerability allows an authenticated administrator with restricted privileges to use a 
    compromised XML API key to perform actions as a higher privileged administrator. For example, 
    a read-only admin could perform write operations using a higher privileged admin's API key.
    
    Fixed versions:
    - PAN-OS 10.1.11 and later
    - PAN-OS 10.2.8 and later
    - PAN-OS 11.0.3 and later
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
        {'version': '9.0.0', 'lessThan': '9.0.17-h4'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.1.0', 'lessThan': '10.1.11'},
        {'version': '10.2.0', 'lessThan': '10.2.8'},
        {'version': '11.0.0', 'lessThan': '11.0.3'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if XML API is enabled
    config = commands.show_running_config
    if 'mgmt-config' not in config or 'api' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-9471. "
        "The device is running a vulnerable version and has XML API enabled, "
        "which could allow privilege escalation through compromised API keys. "
        "Upgrade to a fixed version: 10.1.11+, 10.2.8+, or 11.0.3+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-9471"
    )
