from comfy import medium

@medium(
    name='rule_cve202439527',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_system_users='show system users',
        show_config_login='show configuration | display set | match "system login class"'
    )
)
def rule_cve202439527(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39527 vulnerability in Juniper Networks Junos OS on SRX Series.
    The vulnerability allows a local, low-privileged user with CLI access to view the contents of
    protected files on the file system through crafted CLI commands.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S8
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S5
        '22.2R3-S4', '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S4
        '22.3R3-S3', '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S4
        '22.4R3-S3', '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S2
        '23.2R2-S1', '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for non-root users with CLI access
    users_output = commands.show_system_users
    login_config = commands.show_config_login

    # Look for login classes with restricted permissions
    restricted_classes = any(
        'class' in line and not any(priv in line for priv in ['super-user', 'all-permissions'])
        for line in login_config.splitlines()
    )

    # Check if any non-root users are currently logged in
    active_users = len([line for line in users_output.splitlines() if 'root' not in line]) > 0

    # Device is at risk if it has restricted users configured or active
    at_risk = restricted_classes or active_users

    assert not at_risk, (
        f"Device {device.name} is vulnerable to CVE-2024-39527. "
        "The device is running a vulnerable version with non-privileged users who could "
        "access protected files through crafted CLI commands. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S8, 22.2R3-S5, 22.3R3-S4, 22.4R3-S4, 23.2R2-S2, 23.4R2, 24.2R1, or later. "
        "As a workaround, limit CLI access to trusted hosts and administrators using access lists or firewall filters. "
        "For more information, see https://supportportal.juniper.net/JSA88104"
    )
