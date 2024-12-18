from comfy import high


@high(
    name='rule_cve20240009',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20240009(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-0009 in PAN-OS devices.
    The vulnerability allows a malicious user with stolen credentials to establish a VPN connection
    from an unauthorized IP address when GlobalProtect gateway is enabled.
    
    Fixed versions:
    - PAN-OS 10.2.4 and later
    - PAN-OS 11.0.1 and later
    """
    # Extract version information
    version = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 10.2.', 'sw-version: 11.0.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in version for v in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
        
    # Check if GlobalProtect gateway is enabled
    config = commands.show_global_protect
    if 'GlobalProtect' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-0009. "
        "The device is running a vulnerable version and has GlobalProtect gateway enabled, "
        "which could allow unauthorized VPN connections from malicious users with stolen credentials. "
        "Upgrade to a fixed version: 10.2.4+ or 11.0.1+. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-0009"
    )
