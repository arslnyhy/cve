from comfy import medium

@medium(
    name='rule_cve202421618',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_lldp='show configuration | display set | match "protocols lldp interface"',
        show_processes='show system processes extensive | match l2cpd'
    )
)
def rule_cve202421618(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21618 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an adjacent, unauthenticated attacker to cause Denial of Service (DoS)
    by sending malformed LLDP packets that cause l2cpd crash and restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 21.4R1 are not affected
    if not any(ver in version_output for ver in ['21.4', '22.1', '22.2', '22.3', '22.4', '23.2']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        # 22.1 versions before 22.1R3-S4
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3',
        # 22.2 versions before 22.2R3-S2
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1',
        # 22.3 versions before 22.3R2-S2, 22.3R3-S1
        '22.3R1', '22.3R2', '22.3R2-S1', '22.3R3',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # 21.4 versions before 21.4R3-S5-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO', '21.4R3-S1-EVO',
        '21.4R3-S2-EVO', '21.4R3-S3-EVO', '21.4R3-S4-EVO',
        # 22.1 versions before 22.1R3-S4-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO', '22.1R3-S1-EVO',
        '22.1R3-S2-EVO', '22.1R3-S3-EVO',
        # 22.2 versions before 22.2R3-S2-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO', '22.2R3-S1-EVO',
        # 22.3 versions before 22.3R2-S2-EVO, 22.3R3-S1-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R2-S1-EVO', '22.3R3-EVO',
        # 22.4 versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2 versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if LLDP is enabled on any interface
    lldp_config = commands.show_config_lldp
    lldp_enabled = 'protocols lldp interface' in lldp_config

    if not lldp_enabled:
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
        f"Device {device.name} is vulnerable to CVE-2024-21618. "
        "The device is running a vulnerable version with LLDP enabled and showing signs "
        "of l2cpd crashes. This can lead to STP protocol reinitialization and service disruption. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3-S4, 22.1R3-S4, 22.2R3-S2, 22.3R2-S2, 22.3R3-S1, 22.4R3, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: 21.4R3-S5-EVO, 22.1R3-S4-EVO, 22.2R3-S2-EVO, 22.3R2-S2-EVO, "
        "22.3R3-S1-EVO, 22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO or later. "
        "For more information, see https://supportportal.juniper.net/JSA75759"
    )
