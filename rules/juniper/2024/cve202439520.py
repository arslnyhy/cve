from comfy import high

@high(
    name='rule_cve202439520',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_system_users='show system users',
        show_config_login='show configuration | display set | match "system login"'
    )
)
def rule_cve202439520(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39520 through CVE-2024-39524 vulnerabilities in Juniper Networks
    Junos OS Evolved. These vulnerabilities allow a local, authenticated attacker with low privileges
    to escalate their privileges to 'root' by exploiting improper CLI parameter handling.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos OS Evolved and is affected platform
    version_output = commands.show_version
    chassis_output = commands.show_chassis_hardware

    if 'Evolved' not in version_output:
        return

    if not any(platform in chassis_output for platform in ['PTX', 'ACX', 'QFX']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S7-EVO versions
        '20.4R3-S6-EVO', '20.4R3-S5-EVO', '20.4R3-S4-EVO', '20.4R3-S3-EVO',
        '20.4R3-S2-EVO', '20.4R3-S1-EVO', '20.4R3-EVO', '20.4R2-EVO', '20.4R1-EVO',
        # 21.2-EVO versions before 21.2R3-S8-EVO
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.4-EVO versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-EVO
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R2-EVO
        '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R2-EVO
        '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for non-root users with CLI access
    users_output = commands.show_system_users
    login_config = commands.show_config_login

    # Look for users with class operator or read-only (potentially vulnerable)
    restricted_users = any(
        'operator' in login_config or 'read-only' in login_config
    )

    # Check if any non-root users are currently logged in
    active_users = 'root' not in users_output

    # Device is at risk if it has restricted users configured or active
    at_risk = restricted_users or active_users

    assert at_risk, (
        f"Device {device.name} is vulnerable to CVE-2024-39520 through CVE-2024-39524. "
        "The device is running a vulnerable version of Junos OS Evolved with non-root users "
        "who could exploit CLI parameter handling to escalate privileges. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S7-EVO, 21.2R3-S8-EVO, 21.4R3-S7-EVO, 22.2R3-EVO, 22.3R2-EVO, "
        "22.4R2-EVO, 23.2R1-EVO, or later. "
        "As a workaround, limit system access to trusted administrators only. "
        "For more information, see https://supportportal.juniper.net/JSA82975"
    )
