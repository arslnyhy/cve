from comfy import medium

@medium(
    name='rule_cve202439560',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_rsvp='show configuration | display set | match "protocols rsvp"',
        show_memory='show system memory',
        show_neighbors='show rsvp neighbor detail'
    )
)
def rule_cve202439560(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39560 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a logically adjacent downstream RSVP neighbor to cause kernel memory
    exhaustion, leading to a kernel crash and Denial of Service (DoS) when the neighbor has a
    persistent error.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 20.4R3-S9
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # All versions of 21.2
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2',
        '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6',
        # 21.4 versions before 21.4R3-S5
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2',
        '21.4R3-S3', '21.4R3-S4',
        # 22.1 versions before 22.1R3-S5
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        '22.1R3-S3', '22.1R3-S4',
        # 22.2 versions before 22.2R3-S3
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2',
        # 22.3 versions before 22.3R3-S2
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # All versions before 21.4R3-S5-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO', '21.4R3-S4-EVO',
        # 22.1-EVO versions before 22.1R3-S5-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO',
        '22.1R3-S1-EVO', '22.1R3-S2-EVO', '22.1R3-S3-EVO', '22.1R3-S4-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO',
        # 22.3-EVO versions before 22.3R3-S2-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO', '22.3R3-S1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if RSVP is configured
    rsvp_config = commands.show_config_rsvp
    rsvp_enabled = 'protocols rsvp' in rsvp_config

    if not rsvp_enabled:
        return

    # Check for memory leak indicators
    memory_output = commands.show_memory
    neighbor_output = commands.show_neighbors

    # Look for high memory utilization
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

    # Look for RSVP neighbors with persistent errors
    error_neighbors = len([line for line in neighbor_output.splitlines() 
                         if 'Error' in line and 'Last error' in line])

    # Device is vulnerable if showing both high memory and RSVP neighbor errors
    is_vulnerable = high_memory and error_neighbors > 0

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39560. "
        "The device is running a vulnerable version with RSVP enabled and showing signs "
        f"of memory exhaustion with {error_neighbors} RSVP neighbors in error state. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S10, 20.4R3-S9, 21.4R3-S5, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, "
        "22.4R3, 23.2R2, 23.4R1, or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83020"
    )
