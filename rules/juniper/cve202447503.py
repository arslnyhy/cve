from comfy import medium

@medium(
    name='rule_cve202447503',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_pim='show configuration | display set | match "protocols pim"',
        show_flowd_crashes='show system core-dumps | match flowd'
    )
)
def rule_cve202447503(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47503 vulnerability in Juniper Networks Junos OS on SRX4600
    and SRX5000 Series. The vulnerability allows an unauthenticated, adjacent attacker to cause
    a Denial of Service (DoS) by sending specific PIM packets that cause flowd crash and restart.

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
        # All versions before 21.4R3-S9
        '21.4R3-S8', '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4',
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S5
        '22.2R3-S4', '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S4
        '22.3R3-S3', '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S4
        '22.4R3-S3', '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S2
        '23.2R2-S1', '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1',
        # 24.2 versions before 24.2R1-S1, 24.2R2
        '24.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if PIM is configured
    pim_config = commands.show_config_pim
    pim_enabled = 'protocols pim' in pim_config

    if not pim_enabled:
        return

    # Check for recent flowd crashes
    crash_output = commands.show_flowd_crashes
    recent_crashes = 'flowd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-47503. "
        "The device is running a vulnerable version with PIM enabled "
        f"and has {recent_crashes} recent flowd crashes. This can indicate exploitation "
        "through specific PIM packets causing service interruption. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S9, 22.2R3-S5, 22.3R3-S4, 22.4R3-S4, 23.2R2-S2, 23.4R2, "
        "24.2R1-S1, 24.2R2, 24.4R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88133"
    )
