from comfy import medium

@medium(
    name='rule_cve202439533',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_filter='show configuration | display set | match "firewall family ethernet-switching filter.*from (ip-source-address|ip-destination-address|arp-type)"',
        show_config_interface='show configuration | display set | match "interfaces.*family ethernet-switching filter output"'
    )
)
def rule_cve202439533(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39533 vulnerability in Juniper Networks Junos OS on QFX5000 Series
    and EX4600 Series. The vulnerability allows an unauthenticated, network-based attacker to bypass
    output firewall filters when using unsupported match conditions, causing integrity impact to
    downstream networks.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is QFX5000 Series or EX4600
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['QFX5', 'EX4600']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S7
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
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for unsupported match conditions in ethernet-switching filters
    filter_config = commands.show_config_filter
    interface_config = commands.show_config_interface

    # Check if any filter with unsupported match conditions is applied as output filter
    unsupported_filters = set()
    applied_filters = set()

    # Get filters with unsupported match conditions
    for line in filter_config.splitlines():
        filter_name = line.split('filter')[1].split()[0]
        unsupported_filters.add(filter_name)

    # Get filters applied as output filters
    for line in interface_config.splitlines():
        if 'filter output' in line:
            filter_name = line.split()[-1]
            applied_filters.add(filter_name)

    # Device is vulnerable if any filter with unsupported conditions is applied as output
    vulnerable_filters = unsupported_filters.intersection(applied_filters)

    assert not vulnerable_filters, (
        f"Device {device.name} is vulnerable to CVE-2024-39533. "
        f"The device is running a vulnerable version with the following output filters using "
        f"unsupported match conditions: {', '.join(vulnerable_filters)}. "
        "These filters will not be effective, allowing traffic to bypass filtering. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S7, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA82993"
    )
