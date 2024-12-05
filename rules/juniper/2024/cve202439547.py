from comfy import high

@high(
    name='rule_cve202439547',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_crpd='show configuration | display set | match "system processes routing"',
        show_task_accounting='show task accounting detail | match "RPD Server"'
    )
)
def rule_cve202439547(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39547 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a CPU-based Denial of
    Service (DoS) by sending crafted TCP traffic to the routing engine that causes high CPU utilization
    in the rpd-server process.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if cRPD is enabled
    crpd_config = commands.show_config_crpd
    if 'system processes routing' not in crpd_config:
        return

    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S7
        '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2',
        '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S6
        '22.1R3-S5', '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S2
        '22.4R3-S1', '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S2
        '23.2R2-S1', '23.2R2', '23.2R1',
        # 24.2 versions before 24.2R2
        '24.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # All versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2 versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R3-S2-EVO
        '22.4R3-S1-EVO', '22.4R3-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for high CPU utilization in RPD Server tasks
    task_output = commands.show_task_accounting
    high_cpu = False
    for line in task_output.splitlines():
        if 'RPD Server' in line:
            try:
                # Extract total time and runs from output
                parts = line.split()
                total_time = float(parts[parts.index('TOT:') + 1])
                runs = int(parts[parts.index('RUNS:') + 1])
                if total_time/runs > 0.0005:  # High average time per run
                    high_cpu = True
                    break
            except (ValueError, IndexError):
                continue

    assert not high_cpu, (
        f"Device {device.name} is vulnerable to CVE-2024-39547. "
        "The device is running a vulnerable version with cRPD enabled and showing signs "
        "of high CPU utilization in rpd-server process. This can indicate exploitation "
        "through crafted TCP traffic. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S8, 21.4R3-S7, 22.1R3-S6, 22.2R3-S4, 22.3R3-S3, 22.4R3-S2, "
        "23.2R2-S2, 24.2R2, or later; "
        "Junos OS Evolved: 21.4R3-S7-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, 22.4R3-S2-EVO, "
        "23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88108"
    )
