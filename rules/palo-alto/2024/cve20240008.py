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
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = ['sw-version: 9.0.', 'sw-version: 9.1.', 'sw-version: 10.0.', 
                         'sw-version: 10.1.', 'sw-version: 10.2.', 'sw-version: 11.0.']
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
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