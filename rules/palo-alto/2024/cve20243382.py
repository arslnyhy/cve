from comfy import high


@high(
    name='rule_cve20243382',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running | match "ssl-forward-proxy"'
    ),
)
def rule_cve20243382(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3382 in PAN-OS configurations.
    The vulnerability is a memory leak that enables an attacker to send a burst of crafted packets 
    through the firewall that eventually prevents the firewall from processing traffic. This issue 
    applies only to PA-5400 Series devices with SSL Forward Proxy enabled.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable versions
    vulnerable_versions = [
        'sw-version: 10.2', 'sw-version: 11.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SSL Forward Proxy/Decryption is enabled
    config = commands.show_running_config
    if 'ssl-forward-proxy' not in config:
        return

    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3382. "
        "The device is running a vulnerable version with SSL Forward Proxy enabled, making it susceptible "
        "to a memory leak that could prevent traffic processing through crafted packets. "
        "Upgrade to a fixed version: 10.2.7-h3+, 11.0.4+, 11.1.2+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3382"
    )
