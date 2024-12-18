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
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = [
        'sw-version: 9.0.', 'sw-version: 9.1.',
        'sw-version: 10.1.', 'sw-version: 10.2.',
        'sw-version: 11.0.'
    ]
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
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
