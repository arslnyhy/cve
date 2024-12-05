from comfy import medium

@medium(
    name='rule_cve202421619',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_web='show configuration | display set | match "system services web-management"'
    )
)
def rule_cve202421619(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21619 vulnerability in Juniper Networks Junos OS on SRX Series
    and EX Series. The vulnerability allows an unauthenticated, network-based attacker to access
    sensitive system information through J-Web temporary files.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX or EX Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['SRX', 'EX']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S5
        '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S2
        '22.3R3-S1', '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if J-Web is enabled (http or https)
    web_config = commands.show_config_web
    web_enabled = any(service in web_config for service in [
        'system services web-management http',
        'system services web-management https'
    ])

    assert not web_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21619. "
        "The device is running a vulnerable version with J-Web enabled. "
        "This configuration can allow an unauthenticated attacker to access sensitive "
        "system information through temporary configuration files. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, "
        "22.3R3-S2, 22.4R3, 23.2R1-S2, 23.2R2, 23.4R1, or later. "
        "As a workaround, disable J-Web or limit access to trusted hosts only. "
        "For more information, see https://supportportal.juniper.net/JSA76390"
    )
