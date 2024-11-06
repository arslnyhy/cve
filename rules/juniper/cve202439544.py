from comfy import medium

@medium(
    name='rule_cve202439544',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_netconf='show configuration | display set | match "system services netconf traceoptions"',
        show_log_perms='file list /var/log/netconflog.log detail'
    )
)
def rule_cve202439544(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39544 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows a low privileged local attacker to view NETCONF traceoptions files
    due to incorrect default permissions, potentially exposing sensitive information.

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
        # All versions before 20.4R3-S9-EVO
        '20.4R3-S8-EVO', '20.4R3-S7-EVO', '20.4R3-S6-EVO', '20.4R3-S5-EVO',
        '20.4R3-S4-EVO', '20.4R3-S3-EVO', '20.4R3-S2-EVO', '20.4R3-S1-EVO',
        '20.4R3-EVO', '20.4R2-EVO', '20.4R1-EVO',
        # 21.2-EVO versions before 21.2R3-S7-EVO
        '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO',
        '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.4-EVO versions before 21.4R3-S5-EVO
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S5-EVO
        '22.1R3-S4-EVO', '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-EVO
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R1-S2-EVO
        '23.2R1-EVO', '23.2R1-S1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if NETCONF traceoptions are configured
    netconf_config = commands.show_config_netconf
    traceoptions_enabled = 'system services netconf traceoptions' in netconf_config

    if not traceoptions_enabled:
        return

    # Check file permissions of netconflog.log
    log_perms = commands.show_log_perms
    incorrect_perms = any([
        'group wheel' in log_perms,  # Should be group root
        'permissions -rw-r--r--' in log_perms  # Should not be world-readable
    ])

    assert not incorrect_perms, (
        f"Device {device.name} is vulnerable to CVE-2024-39544. "
        "The device is running a vulnerable version with NETCONF traceoptions enabled "
        "and incorrect file permissions on netconflog.log, allowing low-privileged users "
        "to access sensitive information. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9-EVO, 21.2R3-S7-EVO, 21.3R3-S5-EVO, 21.4R3-S5-EVO, 22.1R3-S5-EVO, "
        "22.2R3-S3-EVO, 22.3R3-S2-EVO, 22.4R3-EVO, 23.2R1-S2-EVO, 23.2R2-EVO, 23.4R1-EVO, or later. "
        "As a workaround, disable NETCONF traceoptions and fix file permissions with: "
        "'file change-owner group root /var/log/netconflog.log'. "
        "For more information, see https://supportportal.juniper.net/JSA88106"
    )
