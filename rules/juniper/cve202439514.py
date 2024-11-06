from comfy import medium

@medium(
    name='rule_cve202439514',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_evpn='show configuration | display set | match "routing-instances.*instance-type evpn-vpws"',
        show_config_igmp='show configuration | display set | match "routing-instances.*igmp-snooping"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439514(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39514 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by sending specific traffic that causes rpd to crash when EVPN-VPWS and IGMP-snooping are enabled.

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

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if EVPN-VPWS and IGMP-snooping are configured
    evpn_config = commands.show_config_evpn
    igmp_config = commands.show_config_igmp

    evpn_enabled = 'instance-type evpn-vpws' in evpn_config
    igmp_enabled = 'igmp-snooping' in igmp_config

    if not (evpn_enabled and igmp_enabled):
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'rpd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39514. "
        f"The device is running a vulnerable version with EVPN-VPWS and IGMP-snooping enabled, "
        f"and has {recent_crashes} recent rpd crashes. This can indicate exploitation through "
        "specific traffic causing rpd to crash. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S10, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, deactivate IGMP snooping for the EVPN-VPWS instance. "
        "For more information, see https://supportportal.juniper.net/JSA82980"
    )
