from comfy import medium

@medium(
    name='rule_cve202421613',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_te='show configuration | display set | match "protocols (ospf|isis) traffic-engineering"',
        show_task_memory='show task memory detail | match patroot'
    )
)
def rule_cve202421613(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21613 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause an rpd crash through memory
    leak when traffic engineering is enabled and link flaps occur.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.2R3-S3 versions
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S3
        '21.4R3-S2', '21.4R3-S1', '21.4R3',
        '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3
        '22.2R2', '22.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-21.3R3-S5-EVO versions
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-EVO
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-EVO
        '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-EVO
        '22.2R2-EVO', '22.2R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if traffic engineering is enabled for OSPF or ISIS
    te_config = commands.show_config_te
    te_enabled = any(protocol in te_config for protocol in [
        'protocols ospf traffic-engineering',
        'protocols isis traffic-engineering'
    ])

    if not te_enabled:
        return

    # Check for memory leak indicators in patroot
    memory_output = commands.show_task_memory
    memory_lines = memory_output.splitlines()
    
    # Parse memory values for patroot
    current_mem = 0
    peak_mem = 0
    for line in memory_lines:
        if 'patroot' in line:
            parts = line.split()
            if len(parts) >= 6:
                current_mem = int(parts[3])
                peak_mem = int(parts[5])

    # Check for significant memory growth (current usage > 80% of peak)
    memory_leak_detected = peak_mem > 0 and current_mem > 0.8 * peak_mem

    assert not memory_leak_detected, (
        f"Device {device.name} is vulnerable to CVE-2024-21613. "
        "The device is running a vulnerable version with traffic engineering enabled "
        "and showing signs of patroot memory leak. This can lead to rpd crash when link flaps occur. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S3, 21.3R3-S5, 21.4R3-S3, 22.1R3, 22.2R3, 22.3R1, or later; "
        "Junos OS Evolved: 21.3R3-S5-EVO, 21.4R3-EVO, 22.1R3-EVO, 22.2R3-EVO, 22.3R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75754"
    )
