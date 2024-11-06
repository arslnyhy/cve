from comfy import medium

@medium(
    name='rule_cve202439557',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_l2ald='show platform application-info allocations app l2ald-agent',
        show_memory='show system memory'
    )
)
def rule_cve202439557(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39557 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a memory leak in
    the Layer 2 Address Learning Daemon (l2ald), eventually exhausting system memory and
    causing a system crash and Denial of Service (DoS).

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S8-EVO
        '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO',
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO',
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for memory leak in l2ald-agent
    l2ald_output = commands.show_l2ald
    memory_leak = False
    for line in l2ald_output.splitlines():
        if 'net::juniper::rtnh::L2Rtinfo' in line:
            try:
                # Extract values from output
                parts = line.split()
                live = int(parts[parts.index('Live') + 1])
                allocs = int(parts[parts.index('Allocs') + 1])
                # Memory leak indicated by high number of live allocations close to total allocations
                if live > 1000000 and live/allocs > 0.95:  # 95% retention rate
                    memory_leak = True
                    break
            except (ValueError, IndexError):
                continue

    # Check system memory utilization
    memory_output = commands.show_memory
    high_memory = False
    for line in memory_output.splitlines():
        if 'Memory utilization' in line:
            try:
                utilization = int(line.split('%')[0].split()[-1])
                if utilization > 85:  # Memory utilization > 85%
                    high_memory = True
                    break
            except (ValueError, IndexError):
                continue

    # Device is vulnerable if showing both memory leak and high memory utilization
    is_vulnerable = memory_leak and high_memory

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39557. "
        "The device is running a vulnerable version and showing signs of l2ald memory leak "
        "with high system memory utilization. This can lead to system crash when memory is exhausted. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S8-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, 22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83017"
    )
