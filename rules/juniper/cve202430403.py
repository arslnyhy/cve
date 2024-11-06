from comfy import medium

@medium(
    name='rule_cve202430403',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_interfaces='show configuration | display set | match "interfaces.*unit.*family ethernet-switching"',
        show_aftmand_crashes='show system core-dumps | match evo-aftmand-bt',
        show_pfe_status='show pfe statistics error'
    )
)
def rule_cve202430403(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30403 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    through a NULL Pointer Dereference in PFE when MAC learning happens during interface flaps.

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

    # Check if version is 23.2-EVO
    if not '23.2-EVO' in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 23.2-EVO versions before 23.2R1-S1-EVO
        '23.2R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-S1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if Layer 2 switching is configured on any interface
    l2_config = commands.show_config_interfaces
    l2_enabled = 'family ethernet-switching' in l2_config

    if not l2_enabled:
        return

    # Check for signs of evo-aftmand-bt crashes and PFE issues
    aftmand_crashes = commands.show_aftmand_crashes
    pfe_status = commands.show_pfe_status

    # Look for recent crashes and PFE errors
    recent_crashes = len([line for line in aftmand_crashes.splitlines() if 'evo-aftmand-bt' in line])
    pfe_errors = 'error' in pfe_status.lower()

    # Device shows signs of vulnerability if either condition is true
    stability_issues = recent_crashes > 0 or pfe_errors

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30403. "
        "The device is running a vulnerable version of Junos OS Evolved with Layer 2 switching enabled "
        "and showing signs of evo-aftmand-bt crashes or PFE errors. This can indicate exploitation "
        "through MAC learning during interface flaps. "
        "Please upgrade to one of the following fixed versions: "
        "23.2R1-S1-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA79181"
    )
