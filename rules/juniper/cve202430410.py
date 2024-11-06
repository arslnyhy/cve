from comfy import medium

@medium(
    name='rule_cve202430410',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_filter='show configuration | display set | match "firewall family inet6 filter"',
        show_config_interfaces='show configuration | display set | match "interfaces (lo0|ge-)"'
    )
)
def rule_cve202430410(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30410 vulnerability in Juniper Networks Junos OS on EX4300 Series.
    The vulnerability allows traffic intended to the device to reach the RE instead of being discarded
    when the discard term is set in loopback (lo0) interface due to incorrect behavior order.

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
        # All versions before 20.4R3-S10
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
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

    # Check if IPv6 firewall filters are configured on both lo0 and revenue interfaces
    filter_config = commands.show_config_filter
    interface_config = commands.show_config_interfaces

    # Check for IPv6 filters
    has_ipv6_filters = 'firewall family inet6 filter' in filter_config

    # Check for both lo0 and revenue interface filters
    has_lo0_filter = 'interfaces lo0' in interface_config
    has_revenue_filter = any(
        f'interfaces {intf}' in interface_config
        for intf in ['ge-', 'xe-', 'et-']
    )

    # Device is vulnerable if it has IPv6 filters on both lo0 and revenue interfaces
    is_vulnerable = has_ipv6_filters and has_lo0_filter and has_revenue_filter

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-30410. "
        "The device is running a vulnerable version with IPv6 firewall filters configured "
        "on both lo0 and revenue interfaces. This configuration allows traffic to reach "
        "the RE instead of being discarded due to incorrect filter precedence. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S10, 21.2R3-S7, 21.4R3-S6, or later. "
        "As a workaround, apply lo0 filter before the revenue interface filter. "
        "For more information, see https://supportportal.juniper.net/JSA79100"
    )
