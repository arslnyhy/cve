from comfy import medium

@medium(
    name='rule_cve202439561',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_flow='show configuration | display set | match "security flow tcp-session no-syn-check"',
        show_config_offload='show configuration | display set | match "security forwarding-options services-offload"'
    )
)
def rule_cve202439561(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39561 vulnerability in Juniper Networks Junos OS on SRX4600
    and SRX5000 Series. The vulnerability allows an attacker to send TCP packets with SYN/FIN
    or SYN/RST flags, bypassing the expected blocking of these packets when no-syn-check and
    Express Path are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX4600 or SRX5000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['SRX4600', 'SRX5400', 'SRX5600', 'SRX5800']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S7
        '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2',
        '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S6
        '22.1R3-S5', '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S2
        '22.4R3-S1', '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1',
        # 23.4 versions before 23.4R1-S1, 23.4R2
        '23.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if no-syn-check is enabled
    flow_config = commands.show_config_flow
    no_syn_check = 'security flow tcp-session no-syn-check' in flow_config

    # Check if Express Path is enabled
    offload_config = commands.show_config_offload
    express_path = 'security forwarding-options services-offload enable' in offload_config

    # Device is vulnerable if both features are enabled
    is_vulnerable = no_syn_check and express_path

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39561. "
        "The device is running a vulnerable version with both no-syn-check and Express Path enabled. "
        "This configuration allows TCP packets with SYN/FIN or SYN/RST flags to bypass blocking. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8, 21.4R3-S7, 22.1R3-S6, 22.2R3-S4, 22.3R3-S3, 22.4R3-S2, 23.2R2, "
        "23.4R1-S1, 23.4R2, 24.2R1, or later. "
        "As a workaround, disable Express Path using: set security forwarding-options services-offload disable. "
        "For more information, see https://supportportal.juniper.net/JSA83021"
    )
