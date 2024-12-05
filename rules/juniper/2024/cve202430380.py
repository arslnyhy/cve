from comfy import medium

@medium(
    name='rule_cve202430380',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_l2cp='show configuration | display set | match "protocols (lldp|stp|rstp|mstp|vstp|erp)"',
        show_processes='show system processes extensive | match l2cpd'
    )
)
def rule_cve202430380(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30380 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS)
    by sending a specific TLV that causes l2cpd process to crash and layer 2 control protocols to reinitialize.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S4
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S2, 22.3R3-S1
        '22.3R2-S1', '22.3R2', '22.3R1', '22.3R3',
        # 22.4 versions before 22.4R2-S2, 22.4R3
        '22.4R2-S1', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S1, 23.2R2
        '23.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-21.2R3-S7-EVO versions
        '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO',
        '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.3 versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-S5-EVO
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S2-EVO
        '22.2R3-S1-EVO', '22.2R3-EVO', '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R2-S2-EVO, 22.3R3-S1-EVO
        '22.3R2-S1-EVO', '22.3R2-EVO', '22.3R1-EVO', '22.3R3-EVO',
        # 22.4 versions before 22.4R2-S2-EVO, 22.4R3-EVO
        '22.4R2-S1-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R1-S1-EVO, 23.2R2-EVO
        '23.2R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if any layer 2 control protocols are enabled
    l2cp_config = commands.show_config_l2cp
    l2cp_enabled = any(protocol in l2cp_config for protocol in [
        'protocols lldp',
        'protocols stp',
        'protocols rstp',
        'protocols mstp',
        'protocols vstp',
        'protocols erp'
    ])

    if not l2cp_enabled:
        return

    # Check for l2cpd process status
    processes = commands.show_processes
    process_lines = processes.splitlines()
    
    # Look for signs of recent l2cpd crashes or restarts
    crash_indicators = ['core', 'dumped', 'restart', 'killed']
    recent_crashes = any(
        any(indicator in line.lower() for indicator in crash_indicators)
        for line in process_lines
        if 'l2cpd' in line
    )

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-30380. "
        "The device is running a vulnerable version with layer 2 control protocols enabled "
        "and showing signs of l2cpd crashes. This can lead to protocol reinitialization "
        "and service disruption when processing specific TLVs. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S4, 22.1R3-S4, 22.2R3-S2, "
        "22.3R2-S2, 22.3R3-S1, 22.4R2-S2, 22.4R3, 23.2R1-S1, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see https://supportportal.juniper.net/JSA79171"
    )
