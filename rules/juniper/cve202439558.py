from comfy import medium

@medium(
    name='rule_cve202439558',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_pim='show configuration | display set | match "protocols pim"',
        show_config_mofrr='show configuration | display set | match "routing-options multicast stream-protection"',
        show_rpd_crashes='show system core-dumps | match rpd'
    )
)
def rule_cve202439558(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39558 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by sending specific PIM packets that cause rpd to crash when PIM is configured with MoFRR.

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
        # All versions before 20.4R3-S10
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
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
        # 22.3 versions before 22.3R3
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2
        '22.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # All versions before 20.4R3-S10-EVO
        '20.4R3-S9-EVO', '20.4R3-S8-EVO', '20.4R3-S7-EVO', '20.4R3-S6-EVO',
        '20.4R3-S5-EVO', '20.4R3-S4-EVO', '20.4R3-S3-EVO', '20.4R3-S2-EVO',
        '20.4R3-S1-EVO', '20.4R3-EVO',
        # All versions of 21.2-EVO
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO',
        # 21.4-EVO versions before 21.4R3-S9-EVO
        '21.4R3-S8-EVO', '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO',
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S5-EVO
        '22.1R3-S4-EVO', '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-EVO
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R2-EVO
        '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if PIM and MoFRR are configured
    pim_config = commands.show_config_pim
    mofrr_config = commands.show_config_mofrr

    pim_enabled = 'protocols pim' in pim_config
    mofrr_enabled = 'routing-options multicast stream-protection' in mofrr_config

    if not (pim_enabled and mofrr_enabled):
        return

    # Check for recent RPD crashes
    crash_output = commands.show_rpd_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'rpd' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39558. "
        "The device is running a vulnerable version with PIM and MoFRR enabled "
        f"and has {recent_crashes} recent RPD crashes. This can indicate exploitation "
        "through specific PIM packets causing rpd to crash. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S10, 21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3, "
        "22.4R2, 23.2R1, or later; "
        "Junos OS Evolved: 20.4R3-S10-EVO, 21.4R3-S9-EVO, 22.1R3-S5-EVO, 22.2R3-S3-EVO, "
        "22.3R3-EVO, 22.4R2-EVO, 23.2R1-EVO, or later. "
        "As a workaround, disable MoFRR. "
        "For more information, see https://supportportal.juniper.net/JSA83018"
    )
