from comfy import medium

@medium(
    name='rule_cve202430389',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_filter='show configuration | display set | match "interfaces.*filter output"'
    )
)
def rule_cve202430389(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30389 vulnerability in Juniper Networks Junos OS on EX4300 Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause an integrity impact
    by bypassing output firewall filters due to an Incorrect Behavior Order in the PFE.

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

    # Check if version is 21.4
    version_output = commands.show_version
    if not any(ver in version_output for ver in ['21.4R1', '21.4R2', '21.4R3']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S6
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if output firewall filters are configured
    filter_config = commands.show_config_filter
    filter_configured = 'filter output' in filter_config

    assert not filter_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-30389. "
        "The device is running a vulnerable version with output firewall filters configured. "
        "This configuration can allow traffic to bypass filters due to a PFE issue. "
        "Please upgrade to version 21.4R3-S6 or later. "
        "As a temporary workaround, you can deactivate and reactivate the filter, but the issue "
        "may reoccur after a reboot or PFE restart. "
        "For more information, see http://supportportal.juniper.net/JSA79185"
    )
