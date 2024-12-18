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
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 9.1.', 'sw-version: 10.1.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
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
