from comfy import medium

@medium(
    name='rule_cve202421610',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_cos='show configuration | display set | match "class-of-service"',
        show_processes='show system processes extensive | match mgd | match sbwait',
        show_config_ssh='show configuration | display set | match "system services ssh"',
        show_config_telnet='show configuration | display set | match "system services telnet"',
        show_config_netconf='show configuration | display set | match "system services netconf"'
    )
)
def rule_cve202421610(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21610 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an authenticated, network-based attacker with low privileges to cause
    a limited Denial of Service (DoS) by causing mgd processes to get stuck when gathering CoS
    information in a scaled subscriber scenario.
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
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S2
        '22.3R3-S1', '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if CoS is configured
    cos_config = commands.show_config_cos
    cos_configured = 'class-of-service' in cos_config

    if not cos_configured:
        return

    # Check if any remote management services are enabled
    ssh_config = commands.show_config_ssh
    telnet_config = commands.show_config_telnet
    netconf_config = commands.show_config_netconf

    remote_access_enabled = any([
        'system services ssh' in ssh_config,
        'system services telnet' in telnet_config,
        'system services netconf' in netconf_config
    ])

    if not remote_access_enabled:
        return

    # Check for stuck mgd processes
    processes = commands.show_processes
    stuck_processes = len([line for line in processes.splitlines() if 'sbwait' in line])

    assert stuck_processes < 5, (  # Alert if more than 5 stuck processes
        f"Device {device.name} is vulnerable to CVE-2024-21610. "
        f"The device is running a vulnerable version with {stuck_processes} stuck mgd processes. "
        "This condition can lead to SSH/NETCONF/telnet session exhaustion when gathering CoS information. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, "
        "22.3R3-S2, 22.4R3, 23.2R1-S2, 23.2R2, 23.4R1, or later. "
        "For more information, see http://supportportal.juniper.net/JSA75751"
    )
