from comfy import medium

@medium(
    name='rule_cve202439543',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_rpki='show configuration | display set | match "routing-options validation"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439543(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39543 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by sending large RPKI-RTR PDU packets that cause rpd to crash due to improper buffer size checking.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output
    
    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S8
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S2
        '22.4R3-S1', '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S1
        '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in junos_vulnerable_versions]
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if RPKI validation is configured
    rpki_config = commands.show_config_rpki
    rpki_enabled = 'routing-options validation' in rpki_config

    if not rpki_enabled:
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = 'rpd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39543. "
        "The device is running a vulnerable version with RPKI validation enabled "
        f"and has {recent_crashes} recent rpd crashes. This can indicate exploitation "
        "through large RPKI-RTR PDU packets. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S8, 21.4R3-S8, 22.2R3-S4, 22.3R3-S3, 22.4R3-S2, "
        "23.2R2-S1, 23.4R2, 24.2R1, or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83004"
    )
