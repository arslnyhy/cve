from comfy import medium

@medium(
    name='rule_cve202439559',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_nsr='show configuration | display set | match "routing-options nonstop-routing"',
        show_config_bgp='show configuration | display set | match "protocols bgp.*authentication-key"',
        show_chassis='show chassis routing-engine | match "Routing Engine"'
    )
)
def rule_cve202439559(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39559 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending specific TCP packets that trigger a race condition in dual RE systems with NSR enabled
    and MD5 authentication configured.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8-EVO
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.4-EVO versions before 21.4R3-S6-EVO
        '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO',
        '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO',
        '22.2R3-EVO', '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R2-S2-EVO, 22.4R3-EVO
        '22.4R2-S1-EVO', '22.4R2-EVO', '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if system has dual REs
    chassis_output = commands.show_chassis
    re_count = len([line for line in chassis_output.splitlines() if 'Routing Engine' in line])
    has_dual_re = re_count > 1

    if not has_dual_re:
        return

    # Check if NSR is enabled
    nsr_config = commands.show_config_nsr
    nsr_enabled = 'routing-options nonstop-routing' in nsr_config

    if not nsr_enabled:
        return

    # Check if BGP MD5 authentication is configured
    bgp_config = commands.show_config_bgp
    md5_enabled = 'authentication-key' in bgp_config

    # Device is vulnerable if all conditions are met
    is_vulnerable = md5_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39559. "
        "The device is running a vulnerable version of Junos OS Evolved with dual REs, "
        "NSR enabled, and BGP MD5 authentication configured. This can allow an attacker "
        "to cause system crash through a race condition in TCP packet processing. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8-EVO, 21.4R3-S6-EVO, 22.1R3-S4-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, "
        "22.4R2-S2-EVO, 22.4R3-EVO, 23.2R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83019"
    )
