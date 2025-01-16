from comfy import high


@high(
    name='rule_cve20243387',
    platform=['paloalto_panorama'],
    commands=dict(
        show_system_info='show system info',
        show_certificate='show device-certificate status'
    ),
)
def rule_cve20243387(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3387 in PAN-OS Panorama appliances.
    The vulnerability is due to weak device certificates that could allow an attacker to perform 
    MitM attacks and potentially decrypt traffic between Panorama and managed firewalls.
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
        {'version': '10.1.0', 'lessThan': '10.1.12'},
        {'version': '10.2.0', 'lessThan': '10.2.7-h3'},
        {'version': '10.2.0', 'lessThan': '10.2.8'},
        {'version': '11.0.0', 'lessThan': '11.0.4'},
    ]
    
    # Check if version is vulnerable using the normalizer function
    version_vulnerable = is_version_affected(version, vulnerable_version_ranges)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # Check if device certificate is not valid
    certificate_output = commands.show_certificate
    if 'No device certificate found' not in certificate_output:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3387. "
        "The Panorama appliance is running a vulnerable version with weak device certificates, "
        "which could allow attackers to perform MitM attacks and decrypt management traffic. "
        "Upgrade to a fixed version: 10.1.12+, 10.2.7-h3+, 10.2.8+, 11.0.4+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3387"
    )
