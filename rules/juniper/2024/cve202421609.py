from comfy import medium

@medium(
    name='rule_cve202421609',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ike='show configuration | display set | match "security ike gateway"',
        show_config_ipsec='show configuration | display set | match "security ipsec vpn"',
        show_processes='show system processes extensive | match "KMD|IKED"'
    )
)
def rule_cve202421609(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21609 vulnerability in Juniper Networks Junos OS on MX Series
    with SPC3 and SRX Series. The vulnerability allows an adjacent attacker to cause a Denial of
    Service (DoS) through memory leak in iked when specific IPsec parameters are negotiated.
    """
    # Check if device is MX Series with SPC3 or SRX Series
    chassis_output = commands.show_chassis_hardware
    if not ('SRX' in chassis_output or ('MX' in chassis_output and 'SPC3' in chassis_output)):
        return

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
        # 22.1 versions before 22.1R3-S3
        '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
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

    # Check if iked is running (vs kmd)
    processes = commands.show_processes
    iked_running = 'IKED' in processes and 'KMD' not in processes

    assert not iked_running, (
        f"Device {device.name} is vulnerable to CVE-2024-21609. "
        "The device is running a vulnerable version with IPsec VPN configured using iked. "
        "This configuration can allow an attacker to cause memory leak and eventual iked crash "
        "through specific IPsec parameter negotiations. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S4, 22.1R3-S3, 22.2R3-S2, "
        "22.3R3, 22.4R3, 23.2R1-S2, 23.2R2, 23.4R1, or later. "
        "For more information, see http://supportportal.juniper.net/JSA75750"
    )
