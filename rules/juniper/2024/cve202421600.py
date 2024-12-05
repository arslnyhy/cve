from comfy import medium

@medium(
    name='rule_cve202421600',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_fti='show configuration | display set | match "interfaces fti0"',
        show_config_ddos='show configuration | display set | match "ddos-protection protocols reject"'
    )
)
def rule_cve202421600(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21600 vulnerability in Juniper Networks Junos OS on PTX Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by sending MPLS packets to a down FTI tunnel, causing a host path wedge condition.
    """
    # Check if device is PTX Series with affected line cards
    chassis_output = commands.show_chassis_hardware
    affected_platforms = ['PTX1000', 'PTX10002-60C', 'PTX10008', 'PTX10016', 'PTX3000', 'PTX5000']
    if not any(platform in chassis_output for platform in affected_platforms):
        return

    # For PTX5000, check if it has FPC3
    if 'PTX5000' in chassis_output and 'FPC3' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S8 versions
        '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.1 versions before 21.1R3-S4
        '21.1R3-S3', '21.1R3-S2', '21.1R3-S1', '21.1R3',
        '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S3
        '21.3R3-S2', '21.3R3-S1', '21.3R3',
        '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R2-S2, 22.1R3
        '22.1R2-S1', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R2-S1, 22.2R3
        '22.2R2', '22.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if FTI is configured
    fti_config = commands.show_config_fti
    fti_enabled = 'interfaces fti0' in fti_config

    if not fti_enabled:
        return

    # Check if DDoS protection for reject packets is configured
    ddos_config = commands.show_config_ddos
    ddos_protected = 'ddos-protection protocols reject aggregate bandwidth 20' in ddos_config

    assert ddos_protected, (
        f"Device {device.name} is vulnerable to CVE-2024-21600. "
        "The device is running a vulnerable version with FTI configured but without DDoS protection for reject packets. "
        "This configuration can allow an attacker to cause a host path wedge condition when FTI tunnel is down. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S8, 21.1R3-S4, 21.2R3-S6, 21.3R3-S3, 21.4R3-S5, 22.1R2-S2, 22.1R3, "
        "22.2R2-S1, 22.2R3, 22.3R1, or later. "
        "As a workaround, configure: system ddos-protection protocols reject aggregate bandwidth 20. "
        "For more information, see https://supportportal.juniper.net/JSA75741"
    )
