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
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 10.1.', 'sw-version: 10.2.', 'sw-version: 11.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

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
