from comfy import high


@high(
    name='rule_cve20245913',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20245913(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5913 in PAN-OS devices.
    The vulnerability is due to improper input validation that could allow an attacker
    with physical access to elevate privileges by tampering with the file system.
    
    Fixed versions:
    - PAN-OS 10.1.14-h2 and later
    - PAN-OS 10.2.10 and later
    - PAN-OS 11.0.5 and later
    - PAN-OS 11.1.4 and later
    - PAN-OS 11.2.1 and later
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
        {'version': '10.1.0', 'lessThan': '10.1.14-h2'},
        {'version': '10.2.0', 'lessThan': '10.2.10'},
        {'version': '11.0.0', 'lessThan': '11.0.5'},
        {'version': '11.1.0', 'lessThan': '11.1.4'},
        {'version': '11.2.0', 'lessThan': '11.2.1'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-5913. "
        "The device is running a vulnerable version which has improper input validation, "
        "potentially allowing privilege escalation through physical file system tampering. "
        "Upgrade to a fixed version: 10.1.14-h2+, 10.2.10+, 11.0.5+, 11.1.4+, or 11.2.1+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-5913"
    )
