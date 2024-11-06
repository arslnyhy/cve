from comfy import high

@high(
    name='rule_cve202421606',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ike='show configuration | display set | match "security ike gateway.*tcp-encap-profile"'
    )
)
def rule_cve202421606(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21606 vulnerability in Juniper Networks Junos OS on SRX Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by triggering a Double Free condition in flowd when tcp-encap-profile is configured.
    """
    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

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
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S3
        '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2-S2
        '22.4R2-S1', '22.4R2', '22.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if tcp-encap-profile is configured in IKE gateway
    ike_config = commands.show_config_ike
    tcp_encap_enabled = 'tcp-encap-profile' in ike_config

    assert not tcp_encap_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21606. "
        "The device is running a vulnerable version with tcp-encap-profile configured in IKE gateway. "
        "This configuration can allow an attacker to cause flowd crashes through a Double Free vulnerability. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S8, 21.2R3-S6, 21.3R3-S5, 21.4R3-S5, 22.1R3-S3, 22.2R3-S3, "
        "22.3R3-S1, 22.4R2-S2, 22.4R3, 23.2R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75747"
    )
