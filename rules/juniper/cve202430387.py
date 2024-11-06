from comfy import medium

@medium(
    name='rule_cve202430387',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_pfe_statistics='show pfe statistics traffic',
        show_interfaces='show interfaces detail'
    )
)
def rule_cve202430387(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30387 vulnerability in Juniper Networks Junos OS on ACX5448 and ACX710.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    by causing interface flaps while statistics are being gathered, leading to PFE crash and restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is ACX5448 or ACX710
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['ACX5448', 'ACX710']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S5
        '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S4
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S2
        '22.1R3-S1', '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R2-S1', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2
        '22.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for signs of PFE issues and interface flaps
    pfe_stats = commands.show_pfe_statistics
    interface_output = commands.show_interfaces

    # Look for PFE errors or crashes
    pfe_issues = any(indicator in pfe_stats.lower() for indicator in [
        'error', 'crash', 'failure', 'restart'
    ])

    # Look for interface flaps
    interface_flaps = any(indicator in interface_output.lower() for indicator in [
        'flapped', 'carrier transitions', 'link down'
    ])

    # Device shows signs of vulnerability if both conditions are present
    stability_issues = pfe_issues and interface_flaps

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30387. "
        "The device is running a vulnerable version and showing signs of PFE issues "
        "and interface flaps. This can lead to PFE crashes due to statistics "
        "gathering during interface transitions. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S5, 21.3R3-S5, 21.4R3-S4, 22.1R3-S2, 22.2R3-S2, "
        "22.3R2-S2, 22.3R3, 22.4R2, 23.2R1, or later. "
        "For more information, see http://supportportal.juniper.net/JSA79187"
    )
