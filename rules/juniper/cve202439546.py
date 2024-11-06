from comfy import high

@high(
    name='rule_cve202439546',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_si='show configuration | display set | match "system services socket-intercept"',
        show_users='show system users | match "uid|gid"'
    )
)
def rule_cve202439546(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39546 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an authenticated, low-privilege local attacker to gain root privileges
    through a Missing Authorization vulnerability in the Socket Intercept (SI) command file interface.

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
        # All versions before 21.2R3-S8-EVO
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.4 versions before 21.4R3-S6-EVO
        '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO',
        '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S5-EVO
        '22.1R3-S4-EVO', '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if Socket Intercept is configured
    si_config = commands.show_config_si
    si_enabled = 'system services socket-intercept' in si_config

    if not si_enabled:
        return

    # Check for non-root users with shell access
    users_output = commands.show_users
    non_root_shells = any(
        'uid=' in line and 'gid=' in line and 'uid=0' not in line
        for line in users_output.splitlines()
    )

    assert not non_root_shells, (
        f"Device {device.name} is vulnerable to CVE-2024-39546. "
        "The device is running a vulnerable version of Junos OS Evolved with Socket Intercept enabled "
        "and non-root users with shell access. This can allow low-privilege users to gain root access "
        "through the SI command file interface. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S6-EVO, 22.1R3-S5-EVO, 22.2R3-S3-EVO, 22.4R3-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83008"
    )
