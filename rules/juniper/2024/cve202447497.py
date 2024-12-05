from comfy import high

@high(
    name='rule_cve202447497',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_web='show configuration | display set | match "system services web-management"',
        show_processes='show system processes extensive | match mgd | count'
    ),
)
def rule_cve202447497(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47497 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS condition
    through uncontrolled resource consumption in the HTTP daemon (httpd) when processing HTTPS requests.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6',
        '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.3R3', '22.3R3-S1', '22.3R3-S2',
        '22.4R3', '22.4R3-S1',
        '23.2R1', '23.2R2',
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX, EX, QFX, or MX Series
    chassis_output = commands.show_chassis_hardware
    is_affected_platform = any(platform in chassis_output for platform in ['SRX', 'EX', 'QFX', 'MX'])

    if not is_affected_platform:
        return

    # Check if web management HTTPS is enabled
    web_config = commands.show_config_web
    https_enabled = 'web-management https' in web_config
    
    # Assert that the device is not vulnerable
    assert not https_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-47497. "
        "The device is running a vulnerable version with HTTPS web management enabled and showing signs of MGD process exhaustion, "
        "which indicates potential exploitation of the httpd vulnerability. "
        "For more information, see https://supportportal.juniper.net/JSA88124"
    )
