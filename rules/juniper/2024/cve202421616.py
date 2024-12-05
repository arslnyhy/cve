from comfy import high

@high(
    name='rule_cve202421616',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_alg_status='show security alg status | match sip',
        show_config_sip='show configuration | display set | match "applications (application|application-set).*sip"',
        show_nat_usage='show security nat resource-usage source-pool'
    )
)
def rule_cve202421616(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21616 vulnerability in Juniper Networks Junos OS on MX Series
    and SRX Series. The vulnerability allows an unauthenticated, network-based attacker to cause
    a Denial of Service (DoS) by sending specific SIP packets that cause NAT IP allocation failure.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series or SRX Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['MX', 'SRX']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.2R3-S6 versions
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2-S2, 22.4R3
        '22.4R2-S1', '22.4R2', '22.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if SIP ALG is enabled
    alg_status = commands.show_alg_status
    sip_enabled = 'SIP : Enabled' in alg_status

    # For MX Series, also check SIP application configuration
    if 'MX' in chassis_output:
        sip_config = commands.show_config_sip
        sip_enabled = sip_enabled or any(config in sip_config for config in [
            'application junos-sip',
            'application-protocol sip',
            'application-set'
        ])

    if not sip_enabled:
        return

    # Check NAT resource usage for signs of exhaustion
    nat_usage = commands.show_nat_usage
    high_usage = False
    for line in nat_usage.splitlines():
        if 'Single Ports' in line:
            try:
                usage = int(line.split()[-2].rstrip('%'))
                if usage > 90:  # Alert if usage is above 90%
                    high_usage = True
                    break
            except (ValueError, IndexError):
                continue

    assert not high_usage, (
        f"Device {device.name} is vulnerable to CVE-2024-21616. "
        "The device is running a vulnerable version with SIP ALG enabled and showing "
        "signs of NAT resource exhaustion. This can lead to NAT allocation failures "
        "and DoS when processing specific SIP packets. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S6, 21.3R3-S5, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, 22.3R3-S1, "
        "22.4R2-S2, 22.4R3, 23.2R1-S1, 23.2R2, 23.4R1, or later. "
        "As a workaround, consider disabling SIP ALG if not strictly needed. "
        "For more information, see https://supportportal.juniper.net/JSA75757"
    )
