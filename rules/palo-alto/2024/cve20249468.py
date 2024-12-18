from comfy import high


@high(
    name='rule_cve20249468',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running'
    ),
)
def rule_cve20249468(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-9468 in PAN-OS devices.
    The vulnerability allows an unauthenticated attacker to crash PAN-OS due to a crafted packet 
    through the data plane, resulting in a denial of service (DoS) condition. Repeated attempts 
    can cause PAN-OS to enter maintenance mode.
    
    Fixed versions:
    - PAN-OS 10.2.9-h11 and later
    - PAN-OS 10.2.10-h4 and later
    - PAN-OS 10.2.11 and later
    - PAN-OS 11.0.4-h5 and later
    - PAN-OS 11.0.6 and later
    - PAN-OS 11.1.3 and later
    """
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = [
        'sw-version: 10.2.', 'sw-version: 11.0.', 'sw-version: 11.1.'
    ]
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if Threat Prevention and Anti-Spyware profile are enabled
    config = commands.show_running_config
    if 'threat-prevention' not in config or 'anti-spyware' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-9468. "
        "The device is running a vulnerable version and has Threat Prevention enabled with Anti-Spyware profile, "
        "which could allow an attacker to cause a denial of service condition. "
        "Upgrade to a fixed version: 10.2.9-h11+, 10.2.10-h4+, 10.2.11+, 11.0.4-h5+, 11.0.6+, or 11.1.3+. "
        "Alternatively, disable TP signature 86467 or disable Threat Prevention. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-9468"
    )
