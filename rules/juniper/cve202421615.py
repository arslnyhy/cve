from comfy import medium

@medium(
    name='rule_cve202421615',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_netconf='show configuration | display set | match "system services netconf traceoptions"'
    )
)
def rule_cve202421615(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21615 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows a local, low-privileged attacker to access confidential information when
    NETCONF traceoptions are configured and a super-user performs specific actions via NETCONF.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.2R3-S7 versions
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S5
        '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S2
        '22.3R3-S1', '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2
        '23.2R1', '23.2R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if NETCONF traceoptions is configured
    netconf_config = commands.show_config_netconf
    traceoptions_enabled = 'system services netconf traceoptions' in netconf_config

    assert not traceoptions_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21615. "
        "The device is running a vulnerable version with NETCONF traceoptions enabled. "
        "This configuration can allow low-privileged users to access confidential information "
        "when super-users perform specific actions via NETCONF. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S7, 21.4R3-S5, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3, 23.2R1-S2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see https://supportportal.juniper.net/JSA75756"
    )
