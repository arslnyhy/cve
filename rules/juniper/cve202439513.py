from comfy import medium

@medium(
    name='rule_cve202439513',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_aftmand_crashes='show system core-dumps | match evo-aftmand',
        show_fpc_status='show chassis fpc'
    )
)
def rule_cve202439513(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39513 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows a local, low-privileged attacker to cause a Denial of Service (DoS)
    by executing a specific "clear" command that causes the AFT manager to crash and restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9-EVO versions
        '20.4R3-S8-EVO', '20.4R3-S7-EVO', '20.4R3-S6-EVO', '20.4R3-S5-EVO',
        '20.4R3-S4-EVO', '20.4R3-S3-EVO', '20.4R3-S2-EVO', '20.4R3-S1-EVO',
        '20.4R3-EVO', '20.4R2-EVO', '20.4R1-EVO',
        # 21.2-EVO versions before 21.2R3-S7-EVO
        '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO',
        '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.3-EVO versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4-EVO versions before 21.4R3-S6-EVO
        '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO',
        '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
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

    # Check for recent AFT manager crashes
    crash_output = commands.show_aftmand_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'evo-aftmand' in line])

    # Check for FPC status issues
    fpc_output = commands.show_fpc_status
    fpc_issues = any(
        state in fpc_output.lower()
        for state in ['offline', 'present', 'down']
    )

    # Device shows signs of vulnerability if either condition is true
    stability_issues = recent_crashes > 0 or fpc_issues

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-39513. "
        f"The device is running a vulnerable version and showing signs of instability "
        f"({recent_crashes} recent AFT manager crashes, FPC status issues: {fpc_issues}). "
        "This can indicate exploitation through specific CLI commands. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9-EVO, 21.2R3-S7-EVO, 21.3R3-S5-EVO, 21.4R3-S6-EVO, 22.1R3-S4-EVO, "
        "22.2R3-S3-EVO, 22.3R3-S3-EVO, 22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA82978"
    )
