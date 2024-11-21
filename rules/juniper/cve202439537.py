from comfy import medium

@medium(
    name='rule_cve202439537',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address"',
        show_netstat='show system connections | match LISTEN'
    )
)
def rule_cve202439537(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39537 vulnerability in Juniper Networks Junos OS Evolved on ACX7000 Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause information disclosure and
    availability impact due to wrong initialization that exposes internal processes to network access.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is ACX7000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['ACX7024', 'ACX7100', 'ACX7509']):
        return

    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-S2-EVO
        '22.4R3-S1-EVO', '22.4R3-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO',
        # 23.4-EVO versions before 23.4R1-S1-EVO, 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for firewall filter protecting internal services
    filter_config = commands.show_config_filter
    filter_configured = any(
        'firewall filter mgmt_filter' in filter_config and 'from source-address' in filter_config
    )

    # Check for exposed internal ports
    netstat_output = commands.show_netstat
    exposed_ports = 'LISTEN' in netstat_output

    assert not exposed_ports or filter_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-39537. "
        "The device is running a vulnerable version of Junos OS Evolved with exposed internal ports "
        "and without proper firewall filtering. This can allow an attacker to access internal "
        "processes and cause information disclosure or availability impact. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S7-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, 22.4R3-S2-EVO, 23.2R2-EVO, "
        "23.4R1-S1-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "As a workaround, configure firewall filters to limit access to trusted networks. "
        "For more information, see https://supportportal.juniper.net/JSA82997"
    )
