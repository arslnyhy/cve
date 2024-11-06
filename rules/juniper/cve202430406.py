from comfy import high

@high(
    name='rule_cve202430406',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_alg='show configuration | display set | match "security alg"',
        show_flowd_crashes='show system core-dumps | match flowd'
    )
)
def rule_cve202430406(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30406 vulnerability in Juniper Networks Junos OS SRX 5000 Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending crafted packets that trigger a buffer overflow in flowd when ALGs are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX 5000 Series with SPC2
    chassis_output = commands.show_chassis_hardware
    if not ('SRX5' in chassis_output and 'SPC2' in chassis_output):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
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
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if any ALGs are enabled
    alg_config = commands.show_config_alg
    alg_enabled = 'security alg' in alg_config

    if not alg_enabled:
        return

    # Check for recent flowd crashes
    crash_output = commands.show_flowd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'flowd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-30406. "
        f"The device is running a vulnerable version with ALGs enabled and has {recent_crashes} "
        "recent flowd crashes. This can indicate exploitation through crafted packets "
        "triggering a buffer overflow. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, 23.2R2, 23.4R1, or later. "
        "As a workaround, disable as many ALGs as possible until the device can be upgraded. "
        "For more information, see https://supportportal.juniper.net/JSA79104"
    )
