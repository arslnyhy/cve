from comfy import medium


@medium(
    name='rule_cve202439548',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_memory='show system memory node all | match evo-aftmann',
        show_arp='show arp no-resolve | match Incomplete',
        show_ndp='show ipv6 neighbors | match Incomplete'
    )
)
def rule_cve202439548(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39548 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through memory leak in the aftmand process when processing unresolved ARP/NDP entries.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S8-EVO
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.3 versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-S5-EVO
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO', '22.1R3-EVO',
        '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R2-S2-EVO, 22.4R3-EVO
        '22.4R2-S1-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R1-S1-EVO, 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(
        version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for memory leak in aftmand process
    memory_output = commands.show_memory
    memory_leak = False
    for line in memory_output.splitlines():
        if 'evo-aftmann' in line:
            try:
                # Extract memory values (current and peak)
                values = line.split()
                current = int(values[3])
                peak = int(values[5])
                if current > 0.8 * peak:  # Memory usage > 80% of peak
                    memory_leak = True
                    break
            except (ValueError, IndexError):
                continue

    # Check for high number of unresolved ARP/NDP entries
    arp_output = commands.show_arp
    ndp_output = commands.show_ndp
    incomplete_entries = len([line for line in arp_output.splitlines() if 'Incomplete' in line]) + \
        len([line for line in ndp_output.splitlines() if 'Incomplete' in line])

    # Device is vulnerable if showing memory leak and has high number of unresolved entries
    # Threshold of 100 incomplete entries
    is_vulnerable = memory_leak and incomplete_entries > 100

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39548. "
        "The device is running a vulnerable version and showing signs of aftmand memory leak "
        f"with {incomplete_entries} unresolved ARP/NDP entries. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8-EVO, 21.3R3-S5-EVO, 21.4R3-S5-EVO, 22.1R3-S4-EVO, 22.2R3-S4-EVO, "
        "22.3R3-S3-EVO, 22.4R2-S2-EVO, 22.4R3-EVO, 23.2R1-S1-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "To reduce risk, minimize unresolved ARP/NDP entries in your network. "
        "For more information, see https://supportportal.juniper.net/JSA83010"
    )
