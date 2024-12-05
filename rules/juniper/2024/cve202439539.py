from comfy import medium

@medium(
    name='rule_cve202439539',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_subscriber='show configuration | display set | match "system services subscriber-management"',
        show_fpc_memory='show chassis fpc | match "Memory utilization"'
    )
)
def rule_cve202439539(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39539 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS)
    through memory leak in FPC when continuous subscriber logins occur.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    if 'MX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S5
        '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S2
        '22.3R3-S1', '22.3R3', '22.3R2', '22.3R1',
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

    # Check if subscriber management is enabled
    subscriber_config = commands.show_config_subscriber
    subscriber_enabled = 'system services subscriber-management enable' in subscriber_config

    if not subscriber_enabled:
        return

    # Check for high memory utilization in FPCs (indicating potential memory leak)
    memory_output = commands.show_fpc_memory
    high_memory = False
    for line in memory_output.splitlines():
        if 'Memory utilization' in line:
            try:
                utilization = int(line.split()[-1].rstrip('%'))
                if utilization > 80:  # Alert if any FPC has >80% memory utilization
                    high_memory = True
                    break
            except (ValueError, IndexError):
                continue

    assert not high_memory, (
        f"Device {device.name} is vulnerable to CVE-2024-39539. "
        "The device is running a vulnerable version with subscriber management enabled "
        "and showing signs of FPC memory leak. This can lead to FPC crashes when "
        "continuous subscriber logins occur. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S6, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, 23.2R2, 23.4R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA82999"
    )
