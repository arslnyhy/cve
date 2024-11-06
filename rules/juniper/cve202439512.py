from comfy import medium

@medium(
    name='rule_cve202439512',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_system_users='show system users',
        show_system_login='show configuration | display set | match "system login"'
    )
)
def rule_cve202439512(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39512 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an attacker with physical access to gain unauthorized access
    through a console session that remains active after cable disconnection.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 23.2 versions before 23.2R2-S1-EVO
        '23.2R2-EVO',
        # 23.4 versions before 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for active console sessions
    users_output = commands.show_system_users
    console_sessions = len([line for line in users_output.splitlines() if 'console' in line.lower()])

    # Check if console timeout is configured
    login_config = commands.show_system_login
    timeout_configured = 'system login idle-timeout' in login_config

    # Device is vulnerable if it has console sessions and no timeout configured
    is_vulnerable = console_sessions > 0 and not timeout_configured

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39512. "
        f"The device is running a vulnerable version with {console_sessions} active console "
        "sessions and no idle timeout configured. This allows an attacker with physical access "
        "to gain unauthorized access through disconnected console sessions. "
        "Please upgrade to one of the following fixed versions: "
        "23.2R2-S1-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "As a workaround, limit physical access to trusted administrators only. "
        "For more information, see https://supportportal.juniper.net/JSA82977"
    )
