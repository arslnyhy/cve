from comfy import medium

@medium(
    name='rule_cve202430402',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_telemetry='show configuration | display set | match "services analytics streaming-server"',
        show_l2ald_crashes='show system core-dumps | match l2ald',
        show_drend_status='show system processes extensive | match drend'
    )
)
def rule_cve202430402(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30402 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    when telemetry requests are sent and the Dynamic Rendering Daemon (drend) is suspended.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S10 versions
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
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
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-21.4R3-S5-EVO versions
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S1-EVO
        '22.3R3-EVO', '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if telemetry is configured
    telemetry_config = commands.show_config_telemetry
    telemetry_enabled = 'services analytics streaming-server' in telemetry_config

    if not telemetry_enabled:
        return

    # Check for l2ald crashes and drend status
    l2ald_crashes = commands.show_l2ald_crashes
    drend_status = commands.show_drend_status

    # Look for recent crashes and drend issues
    recent_crashes = len([line for line in l2ald_crashes.splitlines() if 'l2ald' in line])
    drend_suspended = 'suspended' in drend_status.lower()

    # Device shows signs of vulnerability if both conditions are present
    stability_issues = recent_crashes > 0 and drend_suspended

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30402. "
        "The device is running a vulnerable version with telemetry enabled and showing "
        "signs of l2ald crashes with suspended drend process. This can lead to "
        "sustained DoS when receiving telemetry requests. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S10, 21.2R3-S7, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, 22.3R3-S1, "
        "22.4R3, 23.2R1-S2, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see https://supportportal.juniper.net/JSA79180"
    )
