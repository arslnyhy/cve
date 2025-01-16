from comfy import high


@high(
    name='rule_cve20240008',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info'
    ),
)
def rule_cve20240008(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0008 in PAN-OS devices.
    The vulnerability is due to web sessions in the management interface not expiring
    in certain situations, making it susceptible to unauthorized access.
    
    Fixed versions:
    - PAN-OS 9.0.17-h2 and later
    - PAN-OS 9.1.17 and later
    - PAN-OS 10.0.12-h1 and later
    - PAN-OS 10.1.10-h1 and later
    - PAN-OS 10.2.5 and later
    - PAN-OS 11.0.2 and later
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
        {'version': '9.0.0', 'lessThan': '9.0.17-h2'},
        {'version': '9.1.0', 'lessThan': '9.1.17'},
        {'version': '10.0.0', 'lessThan': '10.0.12-h1'},
        {'version': '10.1.0', 'lessThan': '10.1.10-h1'},
        {'version': '10.2.0', 'lessThan': '10.2.5'},
        {'version': '11.0.0', 'lessThan': '11.0.2'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0008. "
        "The device is running a vulnerable version which has insufficient session expiration in the web interface. "
        "This could allow unauthorized access to the management interface. "
        "Upgrade to a fixed version: 9.0.17-h2+, 9.1.17+, 10.0.12-h1+, 10.1.10-h1+, 10.2.5+, or 11.0.2+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0008"
    )