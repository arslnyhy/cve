from comfy import medium

@medium(
    name='rule_cve202439538',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_multicast='show configuration | display set | match "protocols (pim|igmp)"',
        show_fpc_crashes='show system core-dumps | match evo-pfemand'
    )
)
def rule_cve202439538(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39538 vulnerability in Juniper Networks Junos OS Evolved on ACX7000 Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    through a buffer copy vulnerability in evo-pfemand when processing specific multicast traffic.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is ACX7000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['ACX7024', 'ACX7100', 'ACX7509']):
        return

    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8-EVO
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.4-EVO versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-S2-EVO
        '22.4R3-S1-EVO', '22.4R3-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO',
        # 23.4-EVO versions before 23.4R1-S2-EVO, 23.4R2-EVO
        '23.4R1-S1-EVO', '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if multicast protocols are configured
    multicast_config = commands.show_config_multicast
    multicast_enabled = any(protocol in multicast_config for protocol in ['pim', 'igmp'])

    if not multicast_enabled:
        return

    # Check for recent evo-pfemand crashes
    crash_output = commands.show_fpc_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'evo-pfemand' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39538. "
        "The device is running a vulnerable version with multicast enabled "
        f"and has {recent_crashes} recent evo-pfemand crashes. This can indicate exploitation "
        "through specific multicast traffic causing buffer copy vulnerability. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8-EVO, 21.4R3-S7-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, 22.4R3-S2-EVO, "
        "23.2R2-EVO, 23.4R1-S2-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA82998"
    )
