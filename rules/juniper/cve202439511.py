from comfy import medium

@medium(
    name='rule_cve202439511',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_dot1x='show configuration | display set | match "protocols dot1x"',
        show_dot1x_crashes='show system core-dumps | match dot1x'
    )
)
def rule_cve202439511(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39511 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged attacker with CLI access to cause
    a Denial of Service (DoS) by crashing the 802.1X Authentication (dot1x) Daemon
    through a specific operational command.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S10 versions
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
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
        # 22.4 versions before 22.4R3-S1
        '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if 802.1X is configured
    dot1x_config = commands.show_config_dot1x
    dot1x_enabled = 'protocols dot1x' in dot1x_config

    if not dot1x_enabled:
        return

    # Check for recent dot1x daemon crashes
    crash_output = commands.show_dot1x_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'dot1x' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39511. "
        f"The device is running a vulnerable version with 802.1X enabled and has {recent_crashes} "
        "recent dot1x daemon crashes. This can indicate exploitation through specific CLI commands. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S10, 21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, "
        "22.4R3-S1, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA82976"
    )
