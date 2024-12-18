from comfy import high


@high(
    name='rule_cve20248686',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
    ),
)
def rule_cve20248686(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-8686 in PAN-OS devices.
    The vulnerability allows an authenticated administrator to bypass system restrictions 
    and run arbitrary commands as root on the firewall through command injection.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable versions
    vulnerable_versions = [
        'sw-version: 11.2.2'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-8686. "
        "The device is running PAN-OS 11.2.2 which contains a command injection vulnerability "
        "that could allow authenticated administrators to run arbitrary commands as root. "
        "Upgrade to PAN-OS 11.2.3 or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-8686"
    )
