from comfy import medium

@medium(
    name='rule_cve202421605',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_stp='show configuration | display set | match "protocols (stp|mstp|rstp|vstp) interface"'
    )
)
def rule_cve202421605(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21605 vulnerability in Juniper Networks Junos OS on SRX 300 Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by sending specific link-local traffic that gets forwarded to the control plane through STP blocked ports.
    """
    # Check if device is SRX 300 Series
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['SRX300', 'SRX320', 'SRX340', 'SRX345']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions from 21.2R3-S3 to 21.2R3-S5
        '21.2R3-S3', '21.2R3-S4', '21.2R3-S5',
        # 22.1 versions from 22.1R3 to 22.1R3-S3
        '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3',
        # 22.2 versions from 22.2R2 to 22.2R3-S1
        '22.2R2', '22.2R3', '22.2R3-S1',
        # 22.3 versions from 22.3R2 to 22.3R3
        '22.3R2', '22.3R3',
        # 22.4 versions before 22.4R2-S2
        '22.4R1', '22.4R2', '22.4R2-S1',
        # 23.2 versions before 23.2R1-S1
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if at least two interfaces have STP configured
    stp_config = commands.show_config_stp
    stp_interfaces = set()
    for line in stp_config.splitlines():
        if 'interface' in line:
            interface = line.split()[-1]
            stp_interfaces.add(interface)

    # Device is vulnerable if it has 2 or more interfaces with STP
    is_vulnerable = len(stp_interfaces) >= 2

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21605. "
        f"The device is running a vulnerable version with {len(stp_interfaces)} interfaces configured for STP. "
        "This configuration allows link-local traffic through blocked STP ports to reach the control plane, "
        "potentially causing excessive resource consumption and DoS. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S6, 22.1R3-S4, 22.2R3-S2, 22.3R3-S1, 22.4R2-S2, 22.4R3, 23.2R1-S1, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75746"
    )
