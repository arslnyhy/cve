from comfy import medium

@medium(
    name='rule_cve202447495',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_re='show chassis routing-engine',
        show_config_redundancy='show configuration | display set | match "chassis redundancy"'
    )
)
def rule_cve202447495(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47495 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows a locally authenticated attacker with shell access to gain full
    control of the device when Dual Routing Engines (REs) are in use.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    version_output = commands.show_version


    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8-EVO
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO',
        '21.2R3-S1-EVO', '21.2R3-S2-EVO', '21.2R3-S3-EVO',
        '21.2R3-S4-EVO', '21.2R3-S5-EVO', '21.2R3-S6-EVO', '21.2R3-S7-EVO',
        # 21.4-EVO versions before 21.4R3-S8-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '21.4R3-S4-EVO', '21.4R3-S5-EVO', '21.4R3-S6-EVO', '21.4R3-S7-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO', '22.2R3-S3-EVO',
        # 22.3-EVO versions before 22.3R3-S4-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO',
        '22.3R3-S1-EVO', '22.3R3-S2-EVO', '22.3R3-S3-EVO',
        # 22.4-EVO versions before 22.4R3-S3-EVO
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO',
        '22.4R3-S1-EVO', '22.4R3-S2-EVO',
        # 23.2-EVO versions before 23.2R2-S1-EVO
        '23.2R1-EVO', '23.2R2-EVO',
        # 23.4-EVO versions before 23.4R2-S1-EVO
        '23.4R1-EVO', '23.4R2-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if dual REs are present and configured
    re_output = commands.show_chassis_re
    redundancy_config = commands.show_config_redundancy

    # Count number of REs
    re_count = len([line for line in re_output.splitlines() if 'Routing Engine' in line])

    # Check if redundancy is configured
    redundancy_enabled = 'chassis redundancy' in redundancy_config

    # Device is vulnerable if it has dual REs and redundancy configured
    is_vulnerable = re_count > 1 and redundancy_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-47495. "
        "The device is running a vulnerable version of Junos OS Evolved with dual REs configured. "
        "This configuration can allow a local attacker with shell access to gain full control "
        "through an authorization bypass vulnerability. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8-EVO, 21.4R3-S8-EVO, 22.2R3-S4-EVO, 22.3R3-S4-EVO, 22.4R3-S3-EVO, "
        "23.2R2-S1-EVO, 23.4R2-S1-EVO, 24.2R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://kb.juniper.net/JSA88122"
    )
