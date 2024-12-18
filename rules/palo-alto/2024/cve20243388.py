from comfy import high


@high(
    name='rule_cve20243388',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_running_config='show config running',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20243388(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3388 in PAN-OS configurations.
    The vulnerability in GlobalProtect Gateway allows an authenticated attacker to impersonate 
    another user and send network packets to internal assets when SSL VPN is enabled.
    """
    # Extract version information
    version_output = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 8.1.', 'sw-version: 9.0.', 'sw-version: 9.1.', 'sw-version: 10.1.', 'sw-version: 10.2.', 'sw-version: 11.0.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if GlobalProtect gateway is configured
    config = commands.show_global_protect
    if 'Gateway' not in config:
        return

    # Check if SSL VPN is enabled
    config = commands.show_running_config
    if ('ssl' not in config and 'tls' not in config):
        return
        
    # Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3388. "
        "The device is running a vulnerable version and has GlobalProtect gateway configured "
        "with SSL VPN enabled (either as fallback or primary mode), which could allow "
        "authenticated users to impersonate others and send packets to internal assets. "
        "Upgrade to a fixed version: 8.1.26+, 9.0.17-h4+, 9.1.17+, 10.1.11-h4+, 10.2.7-h3+, 11.0.3+, or later. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3388"
    )
