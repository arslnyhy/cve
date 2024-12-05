from comfy import medium

@medium(
    name='rule_cve202439532',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_system_users='show system users',
        show_config_login='show configuration | display set | match "system login class"',
        show_log_files='show log messages | last 100'
    )
)
def rule_cve202439532(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39532 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a local, authenticated attacker with high privileges to access sensitive
    information stored in plain text in log files when other users perform specific operations.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 22.1R2-S2
        '22.1R2-S1', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R2-S1, 22.2R3
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R1-S2, 22.3R2
        '22.3R1-S1', '22.3R1'
    ]

    # List of vulnerable software versions for Junos OS Evolved
    evo_vulnerable_versions = [
        # All versions before 22.1R3-EVO
        '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R2-S1-EVO, 22.2R3-EVO
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R1-S1-EVO, 22.3R2-EVO
        '22.3R1-EVO'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    is_evo = 'Evolved' in version_output
    vulnerable_versions = evo_vulnerable_versions if is_evo else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for users with high privileges
    login_config = commands.show_config_login
    high_priv_classes = any(
        'permissions all' in line or 'super-user' in line
        for line in login_config.splitlines()
    )

    if not high_priv_classes:
        return

    # Check for active users
    users_output = commands.show_system_users
    multiple_users = len(users_output.splitlines()) > 2  # More than root and current user

    if not multiple_users:
        return

    # Check for sensitive information in logs
    log_output = commands.show_log_files
    sensitive_patterns = [
        'password', 'secret', 'key', 'credential', 'auth',
        'certificate', 'private', 'token', 'hash'
    ]
    sensitive_info = any(
        pattern in line.lower() for pattern in sensitive_patterns
        for line in log_output.splitlines()
    )

    assert not sensitive_info, (
        f"Device {device.name} is vulnerable to CVE-2024-39532. "
        "The device is running a vulnerable version with high-privileged users and "
        "showing signs of sensitive information in log files. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 22.1R2-S2, 22.2R2-S1, 22.2R3, 22.3R1-S2, 22.3R2, 22.4R1, or later; "
        "Junos OS Evolved: 22.1R3-EVO, 22.2R2-S1-EVO, 22.2R3-EVO, 22.3R1-S1-EVO, 22.3R2-EVO, "
        "22.4R1-EVO, or later. "
        "As a workaround, limit device access to trusted administrative networks using firewall filters. "
        "For more information, see https://supportportal.juniper.net/JSA82992"
    )
