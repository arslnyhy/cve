from comfy import medium

@medium(
    name='rule_cve202447498',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_mac_limit='show configuration | display set | match "(switch-options|l2-learning|mac-move-limit)"'
    )
)
def rule_cve202447498(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47498 vulnerability in Juniper Networks Junos OS Evolved on QFX5000 Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by exploiting non-functional MAC learning and move limits, leading to control plane overload.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is QFX5000 Series running Junos OS Evolved
    chassis_output = commands.show_chassis_hardware
    version_output = commands.show_version
    
    if not ('QFX5' in chassis_output and 'Evolved' in version_output):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S8-EVO
        '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO',
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO',
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S5-EVO
        '22.2R3-S4-EVO', '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO',
        '22.2R3-EVO', '22.2R2-EVO', '22.2R1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for any MAC learning/move limit configurations that won't take effect
    mac_config = commands.show_config_mac_limit
    vulnerable_configs = [
        'switch-options interface-mac-limit',
        'switch-options interface.*interface-mac-limit',
        'vlans.*switch-options interface.*interface-mac-limit',
        'vlans.*switch-options mac-table-size',
        'protocols l2-learning global-mac-limit',
        'vlans.*switch-options mac-move-limit'
    ]

    # Device is vulnerable if any of these configurations are present
    is_vulnerable = any(config in mac_config for config in vulnerable_configs)

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-47498. "
        "The device is running a vulnerable version of Junos OS Evolved with MAC learning/move limits "
        "configured that do not take effect. This can allow an attacker to cause control plane overload "
        "through MAC address flooding. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S8-EVO, 22.2R3-S5-EVO, 22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88128"
    )
