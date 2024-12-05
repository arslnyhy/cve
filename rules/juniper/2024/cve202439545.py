from comfy import high

@high(
    name='rule_cve202439545',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ike='show configuration | display set | match "security ike gateway"',
        show_config_ipsec='show configuration | display set | match "security ipsec vpn"',
        show_iked_crashes='show system core-dumps | match iked'
    )
)
def rule_cve202439545(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39545 vulnerability in Juniper Networks Junos OS on SRX Series,
    MX Series with SPC3, and NFX350. The vulnerability allows an unauthenticated, network-based
    attacker to cause a Denial of Service (DoS) by sending mismatching IPsec parameters that
    trigger an iked crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series, MX Series with SPC3, or NFX350
    chassis_output = commands.show_chassis_hardware
    is_srx = 'SRX' in chassis_output
    is_nfx = 'NFX350' in chassis_output
    is_mx_spc3 = 'MX' in chassis_output and 'SPC3' in chassis_output

    if not (is_srx or is_nfx or is_mx_spc3):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S7
        '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2',
        '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S2
        '22.1R3-S1', '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S1
        '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S1, 22.3R3
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R1-S2, 22.4R2, 22.4R3
        '22.4R1', '22.4R2'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if IKE and IPsec VPN are configured
    ike_config = commands.show_config_ike
    ipsec_config = commands.show_config_ipsec
    vpn_configured = 'security ike gateway' in ike_config and 'security ipsec vpn' in ipsec_config

    if not vpn_configured:
        return

    # Check for recent iked crashes
    crash_output = commands.show_iked_crashes
    recent_crashes = 'iked' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39545. "
        "The device is running a vulnerable version with IPsec VPN configured "
        f"and has {recent_crashes} recent iked crashes. This can indicate exploitation "
        "through mismatching IPsec parameters. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8, 21.4R3-S7, 22.1R3-S2, 22.2R3-S1, 22.3R2-S1, 22.3R3, "
        "22.4R1-S2, 22.4R2, 22.4R3, 23.2R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83007"
    )
