from comfy import high

@high(
    name='rule_cve202439542',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_cfm='show configuration | display set | match "protocols oam ethernet connectivity-fault-management"',
        show_config_sflow='show configuration | display set | match "protocols sflow interfaces"',
        show_fpc_crashes='show system core-dumps | match "packetio|evo-aftman"'
    )
)
def rule_cve202439542(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39542 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through improper input validation in PFE that leads to FPC crash when processing CFM packets or
    sampled ECMP traffic.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is affected platform
    chassis_output = commands.show_chassis_hardware
    is_mx = 'MX' in chassis_output and any(card in chassis_output for card in ['MPC10', 'MPC11', 'LC9600', 'MX304'])
    is_ptx = 'PTX' in chassis_output
    is_acx = 'ACX' in chassis_output

    if not (is_mx or is_ptx or is_acx):
        return

    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output

    # List of vulnerable software versions
    if is_evolved:
        vulnerable_versions = [
            # All versions before 21.2R3-S8-EVO
            '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
            '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
            '21.2R2-EVO', '21.2R1-EVO',
            # 21.4 versions before 21.4R2-EVO
            '21.4R1-EVO'
        ]
    else:
        vulnerable_versions = [
            # All versions before 21.2R3-S4
            '21.2R3-S3', '21.2R3-S2', '21.2R3-S1', '21.2R3',
            '21.2R2', '21.2R1',
            # 21.4 versions before 21.4R2
            '21.4R1',
            # 22.2 versions before 22.2R3-S2
            '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1'
        ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for CFM configuration
    cfm_config = commands.show_config_cfm
    cfm_enabled = 'protocols oam ethernet connectivity-fault-management' in cfm_config

    # Check for SFLOW configuration (only relevant for PTX)
    sflow_config = commands.show_config_sflow
    sflow_enabled = is_ptx and 'protocols sflow interfaces' in sflow_config

    # Device is vulnerable if either feature is enabled
    feature_enabled = cfm_enabled or sflow_enabled

    if not feature_enabled:
        return

    # Check for recent crashes
    crash_output = commands.show_fpc_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'packetio' in line or 'evo-aftman' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39542. "
        "The device is running a vulnerable version with "
        f"{'CFM' if cfm_enabled else 'SFLOW'} enabled and has {recent_crashes} recent "
        "packetio/evo-aftman crashes. This can indicate exploitation through "
        f"{'malformed CFM packets' if cfm_enabled else 'specific ECMP traffic'}. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S4, 21.4R2, 22.2R2-S1, 22.2R3, 22.3R1, or later; "
        "Junos OS Evolved: 21.2R3-S8-EVO, 21.4R2-EVO, 22.2R1-EVO, or later. "
        "As a workaround, disable the affected features. "
        "For more information, see https://supportportal.juniper.net/JSA83002"
    )
