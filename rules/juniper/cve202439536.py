from comfy import medium

@medium(
    name='rule_cve202439536',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bfd='show configuration | display set | match "bfd-liveness-detection authentication"',
        show_config_ppm='show configuration | display set | match "routing-options ppm no-delegate-processing"',
        show_ppm_queue='show ppm request-queue'
    )
)
def rule_cve202439536(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39536 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS)
    through memory leak in ppmd when BFD sessions with authentication flap.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S7
        '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2',
        '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2-S2, 22.4R3
        '22.4R2-S1', '22.4R2', '22.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in junos_vulnerable_versions]
    vulnerable_versions = junos_vulnerable_versions + evo_vulnerable_versions

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BFD with authentication is configured
    bfd_config = commands.show_config_bfd
    bfd_auth_enabled = 'bfd-liveness-detection authentication' in bfd_config

    if not bfd_auth_enabled:
        return

    # Check if delegate processing is disabled (workaround)
    ppm_config = commands.show_config_ppm
    delegate_disabled = 'routing-options ppm no-delegate-processing' in ppm_config

    if delegate_disabled:
        return

    # Check for memory leak signs in ppm request-queue
    queue_output = commands.show_ppm_queue
    queue_lines = queue_output.splitlines()
    
    # Parse total pending requests
    total_pending = 0
    for line in queue_lines:
        if 'request-total-pending:' in line:
            try:
                total_pending = int(line.split()[-1])
            except (ValueError, IndexError):
                continue

    # Alert if pending requests are high (indicating memory leak)
    assert total_pending < 100, (
        f"Device {device.name} is vulnerable to CVE-2024-39536. "
        "The device is running a vulnerable version with BFD authentication enabled "
        f"and showing signs of ppmd memory leak ({total_pending} pending requests). "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S8, 21.4R3-S7, 22.1R3-S4, 22.2R3-S4, 22.3R3, 22.4R2-S2, "
        "22.4R3, 23.2R1, or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, disable delegate processing with: set routing-options ppm no-delegate-processing. "
        "For more information, see https://supportportal.juniper.net/JSA82996"
    )
