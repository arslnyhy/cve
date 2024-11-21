from comfy import high

@high(
    name='rule_cve202439530',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_grpc='show configuration | display set | match "system services extension-service request-response grpc"',
        show_config_netconf='show configuration | display set | match "system services netconf"',
        show_chassisd_crashes='show system core-dumps | match chassisd'
    )
)
def rule_cve202439530(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39530 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by attempting to access specific sensors on platforms not supporting these sensors via GRPC or NETCONF,
    causing chassisd to crash and restart all FPCs.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 21.4 are not affected
    if not any(ver in version_output for ver in ['21.4', '22.1', '22.2', '22.3', '22.4']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R2-S1', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2
        '22.4R1'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if GRPC or NETCONF is enabled
    grpc_config = commands.show_config_grpc
    netconf_config = commands.show_config_netconf

    remote_access_enabled = any([
        'extension-service request-response grpc' in grpc_config,
        'services netconf' in netconf_config
    ])

    if not remote_access_enabled:
        return

    # Check for recent chassisd crashes
    crash_output = commands.show_chassisd_crashes
    recent_crashes = 'chassisd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39530. "
        "The device is running a vulnerable version with GRPC/NETCONF enabled "
        f"and has {recent_crashes} recent chassisd crashes. This can indicate exploitation "
        "through sensor access attempts. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S5, 22.1R3-S4, 22.2R3, 22.3R2-S2, 22.3R3, 22.4R2, 23.2R1, or later. "
        "As a workaround, limit access to trusted administrative networks using firewall filters. "
        "For more information, see https://supportportal.juniper.net/JSA82989"
    )
