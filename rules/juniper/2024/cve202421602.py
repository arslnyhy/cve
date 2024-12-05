from comfy import high

@high(
    name='rule_cve202421602',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware'
    )
)
def rule_cve202421602(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21602 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending specific IPv4 UDP packets that cause packetio crash and restart on the RE.
    """
    # Check if device is ACX Series with affected models
    chassis_output = commands.show_chassis_hardware
    affected_platforms = ['ACX7024', 'ACX7100-32C', 'ACX7100-48L']
    if not any(platform in chassis_output for platform in affected_platforms):
        return

    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # Versions before 21.4R1-EVO are not affected
    if not any(ver in version_output for ver in ['21.4', '22.1', '22.2', '22.3']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S6-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '21.4R3-S4-EVO', '21.4R3-S5-EVO',
        # 22.1 versions before 22.1R3-S5-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO',
        '22.1R3-S1-EVO', '22.1R3-S2-EVO', '22.1R3-S3-EVO',
        '22.1R3-S4-EVO',
        # 22.2 versions before 22.2R2-S1-EVO, 22.2R3-EVO
        '22.2R1-EVO', '22.2R2-EVO',
        # 22.3 versions before 22.3R2-EVO
        '22.3R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21602. "
        "The device is running a vulnerable version that can allow an attacker to cause "
        "packetio crash and restart by sending specific IPv4 UDP packets to the RE. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S6-EVO, 22.1R3-S5-EVO, 22.2R2-S1-EVO, 22.2R3-EVO, 22.3R2-EVO, "
        "22.4R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75743"
    )
