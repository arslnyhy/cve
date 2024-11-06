from comfy import medium

@medium(
    name='rule_cve202421587',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_bfd='show configuration | display set | match "forwarding-options dhcp-relay.*liveness-detection"'
    )
)
def rule_cve202421587(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21587 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an attacker to cause a memory leak in the bbe-smgd process when BFD
    liveness detection for DHCP subscribers is enabled, leading to a Denial of Service (DoS).

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    if 'MX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions
        '22.3R3-S1', '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions
        '22.4R2-S1', '22.4R2', '22.4R1',
        # 23.2 versions
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BFD liveness detection for DHCP subscribers is enabled
    bfd_config = commands.show_config_bfd
    bfd_enabled = 'forwarding-options dhcp-relay liveness-detection' in bfd_config

    assert not bfd_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21587. "
        "The device is running a vulnerable version with BFD liveness detection enabled for DHCP subscribers. "
        "This configuration can lead to memory leak in bbe-smgd process when DHCP subscriber sessions flap. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, 22.3R3-S2, "
        "22.4R2-S2, 22.4R3, 23.2R1-S1, 23.2R2, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75725"
    )
