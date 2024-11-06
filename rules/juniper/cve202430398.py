from comfy import high

@high(
    name='rule_cve202430398',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_pfe_statistics='show pfe statistics traffic',
        show_system_memory='show system memory',
        show_system_core_dumps='show system core-dumps'
    )
)
def rule_cve202430398(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30398 vulnerability in Juniper Networks Junos OS on SRX4600.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through a memory buffer vulnerability in PFE that leads to packet drops and eventual PFE crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX4600
    chassis_output = commands.show_chassis_hardware
    if 'SRX4600' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
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
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for signs of PFE issues
    pfe_stats = commands.show_pfe_statistics
    memory_output = commands.show_system_memory
    core_dumps = commands.show_system_core_dumps

    # Look for indicators of PFE issues
    packet_drops = 'drops' in pfe_stats.lower()
    high_memory = 'Memory utilization is' in memory_output and int(memory_output.split('%')[0].split()[-1]) > 85
    recent_cores = any('pfed' in line for line in core_dumps.splitlines())

    # Device shows signs of vulnerability if any condition is true
    stability_issues = packet_drops or high_memory or recent_cores

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30398. "
        "The device is running a vulnerable version and showing signs of PFE instability "
        "(packet drops, high memory utilization, or PFE core dumps). This can lead to "
        "complete PFE failure requiring manual reboot. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, "
        "23.2R1-S2, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA79176"
    )
