from comfy import high

@high(
    name='rule_cve202421620',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_web='show configuration | display set | match "system services web-management"',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address"'
    ),
)
def rule_cve202421620(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-21620 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an attacker to execute commands with elevated privileges through
    a cross-site scripting (XSS) attack in J-Web if source address restrictions are not properly configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '20.4R3', '20.4R3-S1', '20.4R3-S2', '20.4R3-S3', '20.4R3-S4', '20.4R3-S5',
        '20.4R3-S6', '20.4R3-S7', '20.4R3-S8', '20.4R3-S9',
        '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5',
        '21.2R3-S6', '21.2R3-S7',
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5',
        '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3', '22.1R3-S4',
        '22.2R3', '22.2R3-S1', '22.2R3-S2',
        '22.3R3', '22.3R3-S1',
        '22.4R3',
        '23.2R1',
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX or EX Series
    chassis_output = commands.show_chassis_hardware
    is_affected_platform = any(platform in chassis_output for platform in ['SRX', 'EX'])

    if not is_affected_platform:
        return

    # Check if J-Web is enabled
    web_config = commands.show_config_web
    jweb_enabled = 'web-management' in web_config

    if not jweb_enabled:
        return

    # Check if source address restrictions are configured
    filter_config = commands.show_config_filter
    source_restricted = 'source-address' in filter_config

    # Assert that the device is not vulnerable
    assert not (jweb_enabled and not source_restricted), (
        f"Device {device.name} is vulnerable to CVE-2024-21620. "
        "The device is running a vulnerable version and has J-Web enabled without proper source address restrictions, "
        "which makes it susceptible to XSS attacks. "
        "For more information, see https://supportportal.juniper.net/JSA76390"
    )
