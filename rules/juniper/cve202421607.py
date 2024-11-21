from comfy import medium

@medium(
    name='rule_cve202421607',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_filter='show configuration | display set | match "firewall family inet6 filter.*payload-protocol.*tcp-reset"'
    )
)
def rule_cve202421607(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21607 vulnerability in Juniper Networks Junos OS on MX Series
    and EX9200 Series. The vulnerability allows an unauthenticated, network-based attacker to bypass
    IPv6 firewall filters when payload-protocol match and tcp-reset reject action are configured.
    """
    # Check if device is MX Series or EX9200 Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['MX', 'EX9200']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S7 versions
        '20.4R3-S6', '20.4R3-S5', '20.4R3-S4', '20.4R3-S3',
        '20.4R3-S2', '20.4R3-S1', '20.4R3', '20.4R2', '20.4R1',
        # 21.1 versions before 21.1R3-S5
        '21.1R3-S4', '21.1R3-S3', '21.1R3-S2', '21.1R3-S1',
        '21.1R3', '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R3-S5
        '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S4
        '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S4
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S2
        '22.1R3-S1', '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R2-S1', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R1-S2, 22.4R2-S2, 22.4R3
        '22.4R1-S1', '22.4R1', '22.4R2-S1', '22.4R2'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if IPv6 filter with payload-protocol match and tcp-reset reject is configured
    filter_config = commands.show_config_filter
    vulnerable_config = 'payload-protocol' in filter_config and 'tcp-reset' in filter_config

    assert not vulnerable_config, (
        f"Device {device.name} is vulnerable to CVE-2024-21607. "
        "The device is running a vulnerable version with IPv6 firewall filters using "
        "payload-protocol match and tcp-reset reject action. This configuration allows "
        "packets to be accepted instead of rejected. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S7, 21.1R3-S5, 21.2R3-S5, 21.3R3-S4, 21.4R3-S4, 22.1R3-S2, 22.2R3-S2, "
        "22.3R2-S2, 22.3R3, 22.4R1-S2, 22.4R2-S2, 22.4R3, 23.2R1, or later. "
        "As a workaround, replace payload-protocol match with next-header match. "
        "For more information, see https://supportportal.juniper.net/JSA75748"
    )
