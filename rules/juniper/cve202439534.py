from comfy import medium

@medium(
    name='rule_cve202439534',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address|destination-address"',
        show_config_interface='show configuration | display set | match "interfaces.*unit.*family inet address"'
    )
)
def rule_cve202439534(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39534 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-adjacent attacker to bypass firewall
    filters by using network or broadcast addresses of configured subnets due to incorrect
    address verification.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S8-EVO
        '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO',
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO',
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S4-EVO
        '22.3R3-S3-EVO', '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-S3-EVO
        '22.4R3-S2-EVO', '22.4R3-S1-EVO', '22.4R3-EVO',
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-S1-EVO
        '23.2R2-EVO', '23.2R1-EVO',
        # 23.4-EVO versions before 23.4R1-S2-EVO, 23.4R2-EVO
        '23.4R1-S1-EVO', '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if firewall filters with source/destination address restrictions are configured
    filter_config = commands.show_config_filter
    has_address_filters = any(
        'source-address' in line or 'destination-address' in line
        for line in filter_config.splitlines()
    )

    if not has_address_filters:
        return

    # Check if IPv4 addresses are configured on interfaces
    interface_config = commands.show_config_interface
    has_ipv4_interfaces = 'family inet address' in interface_config

    # Device is vulnerable if it has both address-based filters and IPv4 interfaces
    is_vulnerable = has_address_filters and has_ipv4_interfaces

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39534. "
        "The device is running a vulnerable version of Junos OS Evolved with address-based "
        "firewall filters that can be bypassed using network/broadcast addresses. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S8-EVO, 22.2R3-S4-EVO, 22.3R3-S4-EVO, 22.4R3-S3-EVO, 23.2R2-S1-EVO, "
        "23.4R1-S2-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "As a workaround, use access lists or firewall filters to limit access to trusted hosts. "
        "For more information, see https://supportportal.juniper.net/JSA88105"
    )
