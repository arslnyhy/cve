from comfy import medium

@medium(
    name='rule_cve202430388',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_lacp='show configuration | display set | match "interfaces.*802.3ad|aggregated-ether-options lacp"',
        show_interfaces='show interfaces detail | match "Link flaps"'
    )
)
def rule_cve202430388(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30388 vulnerability in Juniper Networks Junos OS on QFX5000 Series
    and EX Series. The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial
    of Service (DoS) by sending malformed LACP packets that cause link flaps.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is QFX5000 or affected EX Series
    chassis_output = commands.show_chassis_hardware
    affected_platforms = ['QFX5000', 'EX4400', 'EX4100', 'EX4650']
    if not any(platform in chassis_output for platform in affected_platforms):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 20.4 versions from 20.4R3-S4 before 20.4R3-S8
        '20.4R3-S4', '20.4R3-S5', '20.4R3-S6', '20.4R3-S7',
        # 21.2 versions from 21.2R3-S2 before 21.2R3-S6
        '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5',
        # 21.4 versions from 21.4R2 before 21.4R3-S4
        '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        # 22.1 versions from 22.1R2 before 22.1R3-S3
        '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        # 22.2 versions before 22.2R3-S1
        '22.2R1', '22.2R2', '22.2R3',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R1', '22.3R2', '22.3R2-S1',
        # 22.4 versions before 22.4R2-S1, 22.4R3
        '22.4R1', '22.4R2'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if LACP is configured
    lacp_config = commands.show_config_lacp
    lacp_enabled = all(config in lacp_config for config in [
        'ether-options 802.3ad',
        'aggregated-ether-options lacp'
    ])

    if not lacp_enabled:
        return

    # Check for recent LACP flaps
    interface_output = commands.show_interfaces
    flap_lines = [line for line in interface_output.splitlines() if 'Link flaps' in line]
    recent_flaps = any(
        int(line.split(':')[-1].strip()) > 0
        for line in flap_lines
    )

    assert not recent_flaps, (
        f"Device {device.name} is vulnerable to CVE-2024-30388. "
        "The device is running a vulnerable version with LACP configured and showing "
        "signs of link flaps. This can lead to traffic loss when receiving malformed LACP packets. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S8, 21.2R3-S6, 21.3R3-S5, 21.4R3-S4, 22.1R3-S3, 22.2R3-S1, "
        "22.3R2-S2, 22.3R3, 22.4R2-S1, 22.4R3, 23.2R1, or later. "
        "For more information, see http://supportportal.juniper.net/JSA79089"
    )
