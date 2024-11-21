from comfy import medium

@medium(
    name='rule_cve202439554',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp.*multipath"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439554(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39554 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by injecting incremental routing updates when BGP multipath is enabled, causing rpd to crash due to
    a race condition.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output

    # Versions before 21.1R1 are not affected
    if not any(ver in version_output for ver in ['21.1', '21.2', '21.4', '22.1', '22.2', '22.3', '22.4', '23.2']):
        return

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions of 21.1
        '21.1R1', '21.1R2', '21.1R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2',
        '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6',
        # 21.4 versions before 21.4R3-S6
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2',
        '21.4R3-S3', '21.4R3-S4', '21.4R3-S5',
        # 22.1 versions before 22.1R3-S5
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        '22.1R3-S3', '22.1R3-S4',
        # 22.2 versions before 22.2R3-S3
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2',
        # 22.3 versions before 22.3R3-S2
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # All versions of 21.1-EVO and 21.2-EVO
        '21.1R1-EVO', '21.1R2-EVO', '21.1R3-EVO',
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO',
        # 21.4-EVO versions before 21.4R3-S6-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '21.4R3-S4-EVO', '21.4R3-S5-EVO',
        # 22.1-EVO versions before 22.1R3-S5-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO',
        '22.1R3-S1-EVO', '22.1R3-S2-EVO', '22.1R3-S3-EVO', '22.1R3-S4-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO',
        # 22.3-EVO versions before 22.3R3-S2-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO', '22.3R3-S1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP multipath is configured
    bgp_config = commands.show_config_bgp
    multipath_enabled = 'protocols bgp' in bgp_config and 'multipath' in bgp_config

    if not multipath_enabled:
        return

    # Check for recent RPD crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = 'rpd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39554. "
        "The device is running a vulnerable version with BGP multipath enabled "
        f"and has {recent_crashes} recent RPD crashes. This can indicate exploitation "
        "through incremental routing updates causing a race condition. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, "
        "23.2R2, 23.4R1, or later; "
        "Junos OS Evolved: 21.4R3-S6-EVO, 22.1R3-S5-EVO, 22.2R3-S3-EVO, 22.3R3-S2-EVO, "
        "22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83014"
    )
