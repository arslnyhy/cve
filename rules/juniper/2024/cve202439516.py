from comfy import high

@high(
    name='rule_cve202439516',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp"',
        show_config_traceoptions='show configuration | display set | match "protocols bgp.*traceoptions.*detail"',
        show_config_te='show configuration | display set | match "protocols bgp.*family traffic-engineering"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439516(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39516 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a Denial of Service (DoS)
    by sending malformed BGP packets that cause rpd to crash when BGP traceoptions or traffic engineering
    are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.4R3-S8 versions
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S5
        '22.2R3-S4', '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S4
        '22.3R3-S3', '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S3
        '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S2
        '23.2R2-S1', '23.2R2', '23.2R1',
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

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    if 'protocols bgp' not in bgp_config:
        return

    # Check for vulnerable configurations
    traceoptions_config = commands.show_config_traceoptions
    te_config = commands.show_config_te

    traceoptions_enabled = any(config in traceoptions_config for config in [
        'traceoptions packets detail',
        'traceoptions update detail'
    ])
    te_enabled = 'family traffic-engineering unicast' in te_config

    if not (traceoptions_enabled or te_enabled):
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'rpd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39516. "
        f"The device is running a vulnerable version with {'BGP traceoptions' if traceoptions_enabled else 'BGP traffic engineering'} "
        f"enabled and {recent_crashes} recent rpd crashes. This can indicate exploitation through malformed BGP packets. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3-S8, 22.2R3-S5, 22.3R3-S4, 22.4R3-S3, 23.2R2-S2, 23.4R2, 24.2R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, disable BGP traceoptions if not needed for troubleshooting. "
        "For more information, see https://supportportal.juniper.net/JSA88100"
    )
