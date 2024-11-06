from comfy import medium

@medium(
    name='rule_cve202430378',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_gres='show configuration | display set | match "chassis redundancy graceful-switchover"',
        show_config_subscriber='show configuration | display set | match "system services subscriber-management"'
    )
)
def rule_cve202430378(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30378 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows a local, authenticated attacker to cause a Denial of Service (DoS)
    by executing specific CLI commands that cause bbe-smgd to crash when GRES and Subscriber
    Management are enabled.

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
        # Pre-20.4R3-S5 versions
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        '20.4R2', '20.4R1',
        # 21.1 versions before 21.1R3-S4
        '21.1R3-S3', '21.1R3-S2', '21.1R3-S1', '21.1R3',
        '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R3-S3
        '21.2R3-S2', '21.2R3-S1', '21.2R3',
        '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2
        '22.3R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if both GRES and Subscriber Management are enabled
    gres_config = commands.show_config_gres
    subscriber_config = commands.show_config_subscriber

    gres_enabled = 'chassis redundancy graceful-switchover' in gres_config
    subscriber_enabled = 'system services subscriber-management enable' in subscriber_config

    # Device is vulnerable if both features are enabled
    is_vulnerable = gres_enabled and subscriber_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-30378. "
        "The device is running a vulnerable version with both GRES and Subscriber Management enabled. "
        "This configuration can allow an authenticated attacker to cause bbe-smgd crashes through "
        "specific CLI commands. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S5, 21.1R3-S4, 21.2R3-S3, 21.3R3-S5, 21.4R3-S5, 22.1R3, 22.2R3, 22.3R2, "
        "22.4R1, or later. "
        "As a workaround, limit CLI access to trusted hosts and administrators. "
        "For more information, see https://supportportal.juniper.net/JSA79109"
    )
