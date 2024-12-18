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
    # Extract version information
    system_info = commands.show_system_info
    
    # List of vulnerable base versions
    vulnerable_versions = [
        'sw-version: 10.1.', 'sw-version: 10.2.',
        'sw-version: 11.0.', 'sw-version: 11.1.',
        'sw-version: 11.2.'
    ]
    
    # Check if version contains any vulnerable base version
    version_vulnerable = any(v in system_info for v in vulnerable_versions)
    
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
