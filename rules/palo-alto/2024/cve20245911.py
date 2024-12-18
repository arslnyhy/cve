from comfy import high


@high(
    name='rule_cve20245911',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20245911(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-5911 in PAN-OS Panorama appliances.
    The vulnerability allows an authenticated read-write administrator with web interface access
    to upload arbitrary files that could disrupt system processes and crash the Panorama.
    Repeated attacks can cause the Panorama to enter maintenance mode.
    
    Fixed versions:
    - PAN-OS 10.1.9 and later
    - PAN-OS 10.2.4 and later
    - PAN-OS 11.0.0 and later
    """
    # Extract system info
    system_info = commands.show_system_info
    
    # Check if this is a Panorama device
    if 'model: PA' not in system_info:
        return
        
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 10.1.', 'sw-version: 10.2.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-5911. "
        "The Panorama appliance is running a vulnerable version which allows authenticated "
        "read-write administrators to upload arbitrary files that could crash the system. "
        "Upgrade to a fixed version: 10.1.9+, 10.2.4+, or 11.0.0+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-5911"
    )
