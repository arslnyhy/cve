from comfy import high

@high(
    name='rule_cve202439529',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_dga='show configuration | display set | match "services security-metadata-streaming policy.*dns detections (dga|tunneling)"',
        show_config_dns='show configuration | display set | match "services dns-filtering traceoptions"',
        show_pfe_crashes='show system core-dumps | match pfe'
    )
)
def rule_cve202439529(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39529 vulnerability in Juniper Networks Junos OS on SRX Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through a format string vulnerability in PFE when DNS DGA/tunnel detection and traceoptions are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if DGA or tunnel detection is enabled
    dga_config = commands.show_config_dga
    detection_enabled = any(detection in dga_config for detection in [
        'dns detections dga',
        'dns detections tunneling'
    ])

    if not detection_enabled:
        return

    # Check if DNS filtering traceoptions are enabled
    dns_config = commands.show_config_dns
    traceoptions_enabled = 'dns-filtering traceoptions' in dns_config

    if not traceoptions_enabled:
        return

    # Check for recent PFE crashes
    crash_output = commands.show_pfe_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'pfe' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39529. "
        "The device is running a vulnerable version with DNS DGA/tunnel detection and traceoptions enabled, "
        f"and has {recent_crashes} recent PFE crashes. This can indicate exploitation through "
        "specific DNS traffic causing format string vulnerability. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S6, 22.2R3-S3, 22.3R3-S3, 22.4R3, 23.2R2, 23.4R1, or later. "
        "As a workaround, deactivate DNS filtering traceoptions. "
        "For more information, see https://supportportal.juniper.net/JSA82988"
    )
