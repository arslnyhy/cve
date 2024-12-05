from comfy import high

@high(
    name='rule_cve202430395',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202430395(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30395 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending a BGP update with a malformed tunnel encapsulation attribute TLV that causes rpd to crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
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
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-21.2R3-S7-EVO versions
        '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO',
        '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.3-EVO versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4-EVO versions before 21.4R3-S5-EVO
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S2-EVO
        '22.3R3-S1-EVO', '22.3R3-EVO', '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R1-S2-EVO, 23.2R2-EVO
        '23.2R1-EVO', '23.2R1-S1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    bgp_enabled = 'protocols bgp' in bgp_config

    if not bgp_enabled:
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'rpd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-30395. "
        f"The device is running a vulnerable version with BGP enabled and has {recent_crashes} "
        "recent rpd crashes. This can indicate exploitation through malformed BGP tunnel encapsulation attributes. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S7, 21.3R3-S5, 21.4R3-S5, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, "
        "22.4R3, 23.2R1-S2, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see https://supportportal.juniper.net/JSA79095"
    )
