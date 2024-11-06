from comfy import high

@high(
    name='rule_cve202421611',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_jflow='show configuration | display set | match "services flow-monitoring (version-ipfix|version9)"',
        show_task_memory='show task memory detail | match so_in'
    )
)
def rule_cve202421611(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21611 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through memory leak in rpd when BGP next hops are updated in a jflow scenario.
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 21.4R1 are not affected
    if not any(ver in version_output for ver in ['21.4', '22.1', '22.2']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3
        '21.4R1', '21.4R2',
        # 22.1 versions before 22.1R3
        '22.1R1', '22.1R2',
        # 22.2 versions before 22.2R3
        '22.2R1', '22.2R2'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if jflow is configured
    jflow_config = commands.show_config_jflow
    jflow_enabled = any(service in jflow_config for service in [
        'services flow-monitoring version-ipfix',
        'services flow-monitoring version9'
    ])

    if not jflow_enabled:
        return

    # Check for memory leak indicators in so_in buffers
    memory_output = commands.show_task_memory
    memory_lines = memory_output.splitlines()
    
    # Parse memory values for so_in and so_in6
    memory_values = {}
    for line in memory_lines:
        if 'so_in' in line:
            parts = line.split()
            if len(parts) >= 6:
                buffer_type = parts[0]  # so_in or so_in6
                current_mem = int(parts[3])
                peak_mem = int(parts[5])
                memory_values[buffer_type] = (current_mem, peak_mem)

    # Check for significant memory growth (current usage > 80% of peak)
    memory_leak_detected = any(
        current > 0.8 * peak
        for current, peak in memory_values.values()
    )

    assert not memory_leak_detected, (
        f"Device {device.name} is vulnerable to CVE-2024-21611. "
        "The device is running a vulnerable version with jflow configured and showing signs "
        "of memory leak in so_in buffers. This can lead to rpd crash when BGP next hops are updated. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3, 22.1R3, 22.2R3, 22.3R1, or later; "
        "Junos OS Evolved: 21.4R3-EVO, 22.1R3-EVO, 22.2R3-EVO, 22.3R1-EVO, or later. "
        "As a temporary measure, monitor memory utilization and restart rpd when it reaches 85%. "
        "For more information, see https://supportportal.juniper.net/JSA75752"
    )
