from comfy import medium

@medium(
    name='rule_cve202439541',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_te='show configuration | display set | match "protocols (source-packet-routing traffic-engineering|ospf traffic-engineering|isis traffic-engineering)"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439541(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39541 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by adding conflicting information to the TE database, causing rpd to crash and restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 22.4R1 are not affected
    if not any(ver in version_output for ver in ['22.4', '23.2', '23.4']):
        return

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # 22.4 versions before 22.4R3-S1
        '22.4R1', '22.4R2', '22.4R3',
        # 23.2 versions before 23.2R2
        '23.2R1',
        # 23.4 versions before 23.4R1-S1, 23.4R2
        '23.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # 22.4-EVO versions before 22.4R3-S2-EVO
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO', '22.4R3-S1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO',
        # 23.4-EVO versions before 23.4R1-S1-EVO, 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    is_evo = 'Evolved' in version_output
    vulnerable_versions = evo_vulnerable_versions if is_evo else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if traffic engineering features are configured
    te_config = commands.show_config_te
    sr_te_enabled = 'source-packet-routing traffic-engineering database' in te_config
    ospf_te_enabled = 'ospf traffic-engineering' in te_config
    isis_te_enabled = 'isis traffic-engineering' in te_config

    # Device is vulnerable if SR-TE and either OSPF-TE or ISIS-TE are enabled
    te_enabled = sr_te_enabled and (ospf_te_enabled or isis_te_enabled)

    if not te_enabled:
        return

    # Check for recent rpd crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'rpd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39541. "
        "The device is running a vulnerable version with traffic engineering enabled "
        f"and has {recent_crashes} recent rpd crashes. This can indicate exploitation "
        "through conflicting TE database information. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 22.4R3-S1, 23.2R2, 23.4R1-S1, 23.4R2, 24.2R1, or later; "
        "Junos OS Evolved: 22.4R3-S2-EVO, 23.2R2-EVO, 23.4R1-S1-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83001"
    )
