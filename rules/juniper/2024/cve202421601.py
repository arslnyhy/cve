from comfy import medium

@medium(
    name='rule_cve202421601',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware'
    )
)
def rule_cve202421601(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21601 vulnerability in Juniper Networks Junos OS on SRX Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by triggering a race condition in the Flow-processing Daemon (flowd) when processing TCP events.
    """
    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions before 21.2R3-S5
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2',
        '21.2R3-S3', '21.2R3-S4',
        # 21.3 versions before 21.3R3-S5
        '21.3R1', '21.3R2', '21.3R3', '21.3R3-S1', '21.3R3-S2',
        '21.3R3-S3', '21.3R3-S4',
        # 21.4 versions before 21.4R3-S4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2',
        '21.4R3-S3',
        # 22.1 versions before 22.1R3-S3
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        # 22.2 versions before 22.2R3-S1
        '22.2R1', '22.2R2', '22.2R3',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R1', '22.3R2', '22.3R2-S1',
        # 22.4 versions before 22.4R2-S1, 22.4R3
        '22.4R1', '22.4R2'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21601. "
        "The device is running a vulnerable version that can allow an attacker to cause "
        "flowd crashes through a race condition when processing TCP events. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S5, 21.3R3-S5, 21.4R3-S4, 22.1R3-S3, 22.2R3-S1, 22.3R2-S2, "
        "22.3R3, 22.4R2-S1, 22.4R3, 23.2R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75742"
    )
