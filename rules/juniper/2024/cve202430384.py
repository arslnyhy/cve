from comfy import medium

@medium(
    name='rule_cve202430384',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_pfe_statistics='show pfe statistics traffic',
        show_system_core_dumps='show system core-dumps'
    )
)
def rule_cve202430384(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30384 vulnerability in Juniper Networks Junos OS on EX4300 Series.
    The vulnerability allows a locally authenticated attacker with low privileges to cause a
    Denial of Service (DoS) by issuing specific CLI commands that cause PFE crashes.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is EX4300 Series
    chassis_output = commands.show_chassis_hardware
    if 'EX4300' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S10 versions
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        '20.4R2', '20.4R1',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for signs of PFE crashes
    pfe_stats = commands.show_pfe_statistics
    core_dumps = commands.show_system_core_dumps

    # Look for indicators of PFE issues
    pfe_issues = any(indicator in pfe_stats.lower() for indicator in [
        'error', 'crash', 'failure', 'restart'
    ])

    # Look for recent PFE core dumps
    pfe_cores = any('pfed' in line for line in core_dumps.splitlines())

    # Device shows signs of PFE instability if either condition is true
    pfe_instability = pfe_issues or pfe_cores

    assert not pfe_instability, (
        f"Device {device.name} is vulnerable to CVE-2024-30384. "
        "The device is running a vulnerable version and showing signs of PFE instability. "
        "This can lead to traffic forwarding interruption when specific CLI commands are issued. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S10, 21.2R3-S7, 21.4R3-S6, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see http://supportportal.juniper.net/JSA79186"
    )
