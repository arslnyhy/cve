from comfy import high

@high(
    name='rule_cve202439525',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp.*traceoptions"',
        show_bgp_summary='show bgp summary',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439525(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39525 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a Denial of Service (DoS)
    by sending specific BGP packets that cause rpd to crash when BGP traceoptions are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.2R3-S8 versions
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S8
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S4
        '22.3R3-S3', '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S3
        '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S1
        '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP traceoptions are configured
    bgp_config = commands.show_config_bgp
    traceoptions_enabled = any(config in bgp_config for config in [
        'protocols bgp traceoptions',
        'protocols bgp group.*traceoptions',
        'protocols bgp group.*neighbor.*traceoptions'
    ])

    if not traceoptions_enabled:
        return

    # Check if BGP is established
    bgp_summary = commands.show_bgp_summary
    bgp_established = 'Establ' in bgp_summary

    if not bgp_established:
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = 'rpd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39525. "
        f"The device is running a vulnerable version with BGP traceoptions enabled, "
        f"established BGP sessions, and {recent_crashes} recent rpd crashes. "
        "This can indicate exploitation through malformed BGP packets. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S8, 21.4R3-S8, 22.2R3-S4, 22.3R3-S4, 22.4R3-S3, 23.2R2-S1, "
        "23.4R2, 24.2R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, disable BGP traceoptions if not needed for troubleshooting. "
        "For more information, see https://supportportal.juniper.net/JSA88102"
    )
