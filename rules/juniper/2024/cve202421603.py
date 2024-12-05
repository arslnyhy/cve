from comfy import medium

@medium(
    name='rule_cve202421603',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_scu='show configuration | display set | match "source-class"',
        show_config_dcu='show configuration | display set | match "destination-class"',
        show_config_accounting='show configuration | display set | match "accounting.*class-usage"'
    )
)
def rule_cve202421603(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21603 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows a network-based attacker with low privileges to cause a Denial of Service (DoS)
    by gathering statistics in a scaled SCU/DCU configuration, leading to RE kernel crash.
    """
    # Check if device is MX Series with affected line cards
    chassis_output = commands.show_chassis_hardware
    affected_cards = ['MPC10', 'MPC11', 'LC9600', 'MX304']
    if not ('MX' in chassis_output and any(card in chassis_output for card in affected_cards)):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3
        '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R2
        '22.2R1',
        # 22.3 versions before 22.3R2
        '22.3R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Count unique SCU/DCU classes
    scu_config = commands.show_config_scu
    dcu_config = commands.show_config_dcu
    
    scu_classes = set()
    dcu_classes = set()
    
    for line in scu_config.splitlines():
        if 'source-class' in line:
            scu_classes.add(line.split()[-1])
    for line in dcu_config.splitlines():
        if 'destination-class' in line:
            dcu_classes.add(line.split()[-1])

    # Check if accounting is enabled
    accounting_config = commands.show_config_accounting
    accounting_enabled = any(usage in accounting_config for usage in [
        'accounting source-class-usage',
        'accounting destination-class-usage'
    ])

    # Device is vulnerable if it has >10 classes and accounting enabled
    total_classes = len(scu_classes) + len(dcu_classes)
    is_vulnerable = total_classes > 10 and accounting_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21603. "
        f"The device is running a vulnerable version with {total_classes} SCU/DCU classes "
        "and class-usage accounting enabled. This configuration can lead to RE kernel crash "
        "when gathering statistics. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S6, 21.3R3-S5, 21.4R3, 22.1R3, 22.2R2, 22.3R2, 22.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75744"
    )
