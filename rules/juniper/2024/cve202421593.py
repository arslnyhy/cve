from comfy import medium

@medium(
    name='rule_cve202421593',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ccc='show configuration | display set | match "encapsulation ethernet-ccc"'
    )
)
def rule_cve202421593(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21593 vulnerability in Juniper Networks Junos OS MX Series
    with MPC10, MPC11, LC9600, and MX304. The vulnerability allows an unauthenticated, adjacent
    attacker to cause a Denial of Service (DoS) by sending specific MPLS packets that cause
    a PFE crash and restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with affected line cards
    chassis_output = commands.show_chassis_hardware
    affected_cards = ['MPC10', 'MPC11', 'LC9600', 'MX304']
    if not ('MX' in chassis_output and any(card in chassis_output for card in affected_cards)):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S5
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        # 22.2 versions before 22.2R3-S2
        '22.2R2', '22.2R3', '22.2R3-S1',
        # 22.3 versions before 22.3R2-S2
        '22.3R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3',
        # 22.4 versions before 22.4R2-S2
        '22.4R1', '22.4R2', '22.4R2-S1',
        # 23.2 versions before 23.2R1-S1
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if ethernet-ccc encapsulation is configured
    ccc_config = commands.show_config_ccc
    ccc_enabled = 'encapsulation ethernet-ccc' in ccc_config

    assert not ccc_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21593. "
        "The device is running a vulnerable version with ethernet-ccc encapsulation configured. "
        "This configuration can allow an attacker to cause a PFE crash by sending specific MPLS packets. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S5, 22.2R3-S2, 22.2R3-S3, 22.3R2-S2, 22.3R3-S1, 22.4R2-S2, 22.4R3, "
        "23.2R1-S1, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75732"
    )
