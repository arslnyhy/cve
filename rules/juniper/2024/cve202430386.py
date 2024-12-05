from comfy import medium

@medium(
    name='rule_cve202430386',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_evpn='show configuration | display set | match "protocols evpn"',
        show_config_vxlan='show configuration | display set | match "protocols evpn vxlan"',
        show_l2ald='show system processes extensive | match l2ald'
    )
)
def rule_cve202430386(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30386 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by triggering a Use-After-Free condition in l2ald when processing EVPN-VXLAN state updates.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S8 versions
        '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S4
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S3
        '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S1
        '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2
        '22.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-20.4R3-S8-EVO versions
        '20.4R3-S7-EVO', '20.4R3-S6-EVO', '20.4R3-S5-EVO', '20.4R3-S4-EVO',
        '20.4R3-S3-EVO', '20.4R3-S2-EVO', '20.4R3-S1-EVO', '20.4R3-EVO',
        # 21.2 versions before 21.2R3-S6-EVO
        '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO', '21.2R3-S2-EVO',
        '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.3 versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-S4-EVO
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S3-EVO
        '22.1R3-S2-EVO', '22.1R3-S1-EVO', '22.1R3-EVO',
        '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S1-EVO
        '22.2R3-EVO', '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-EVO
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R2-EVO
        '22.4R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if EVPN-VXLAN is configured
    evpn_config = commands.show_config_evpn
    vxlan_config = commands.show_config_vxlan
    evpn_vxlan_enabled = 'protocols evpn' in evpn_config and 'vxlan' in vxlan_config

    if not evpn_vxlan_enabled:
        return

    # Check for l2ald process status
    l2ald_output = commands.show_l2ald
    process_lines = l2ald_output.splitlines()
    
    # Look for signs of recent l2ald crashes or restarts
    crash_indicators = ['core', 'dumped', 'restart', 'killed']
    recent_crashes = any(
        any(indicator in line.lower() for indicator in crash_indicators)
        for line in process_lines
        if 'l2ald' in line
    )

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-30386. "
        "The device is running a vulnerable version with EVPN-VXLAN configured and showing "
        "signs of l2ald crashes. This can lead to DoS when processing state updates. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S8, 21.2R3-S6, 21.3R3-S5, 21.4R3-S4, 22.1R3-S3, 22.2R3-S1, "
        "22.3R3, 22.4R2, 23.2R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see http://supportportal.juniper.net/JSA79184"
    )
