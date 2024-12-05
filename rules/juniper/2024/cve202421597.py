from comfy import medium

@medium(
    name='rule_cve202421597',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_slicing='show configuration | display set | match "chassis network-slices"',
        show_config_ri='show configuration | display set | match "routing-instances"'
    )
)
def rule_cve202421597(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21597 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an unauthenticated, network-based attacker to bypass lo0 firewall
    filters in an Abstracted Fabric (AF) scenario when routing-instances are configured.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    if 'MX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S3
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2
        '22.3R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if node-slicing and routing-instances are configured
    slicing_config = commands.show_config_slicing
    ri_config = commands.show_config_ri

    slicing_enabled = 'chassis network-slices guest-network-functions' in slicing_config
    ri_configured = 'routing-instances' in ri_config

    # Device is vulnerable if both node-slicing and routing-instances are configured
    is_vulnerable = slicing_enabled and ri_configured

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21597. "
        "The device is running a vulnerable version with both node-slicing and routing-instances configured. "
        "This configuration can allow traffic to bypass lo0 firewall filters in AF scenarios. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S3, 21.4R3-S5, 22.1R3, 22.2R3, 22.3R2, 22.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75738"
    )
