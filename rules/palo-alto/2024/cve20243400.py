from comfy import high


@high(
    name='rule_cve20243400',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_global_protect='show global-protect-gateway gateway'
    ),
)
def rule_cve20243400(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-3400 in PAN-OS configurations.
    The vulnerability in GlobalProtect allows an unauthenticated attacker to execute arbitrary code 
    with root privileges through command injection via arbitrary file creation.
    """
    # Extract version information
    system_info = commands.show_system_info

    # List of vulnerable software versions
    vulnerable_versions = [
        'sw-version: 10.2.', 'sw-version: 11.0.', 'sw-version: 11.1.'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in system_info for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    global_protect = commands.show_global_protect
    if 'Gateway' not in global_protect and 'iamportal' not in system_info:
        return

# Assert that the device is not vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2024-3400. "
        "The device is running a vulnerable version and has GlobalProtect gateway or portal configured, "
        "which could allow unauthenticated attackers to execute arbitrary code with root privileges. "
        "This vulnerability is being actively exploited in the wild. "
        "Upgrade to a fixed version: 10.2.9-h1+, 11.0.4-h1+, 11.1.2-h3+, or later. "
        "Enable Threat Prevention with IDs 95187, 95189, and 95191 as a mitigation. "
        "For more details see: https://security.paloaltonetworks.com/CVE-2024-3400"
    )
