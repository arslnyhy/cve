from comfy import high

@high(
    name='rule_cve202421614',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_netconf='show configuration | display set | match "system services netconf"',
        show_config_grpc='show configuration | display set | match "system services extension-service request-response grpc"'
    )
)
def rule_cve202421614(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21614 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause rpd to crash through
    a specific query via Dynamic Rendering (DREND) when NETCONF and gRPC are enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 22.2R1 are not affected
    if not any(ver in version_output for ver in ['22.2', '22.3']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 22.2 versions before 22.2R2-S2, 22.2R3
        '22.2R1', '22.2R2', '22.2R2-S1',
        # 22.3 versions before 22.3R2, 22.3R3
        '22.3R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # 22.2 versions before 22.2R2-S2-EVO, 22.2R3-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R2-S1-EVO',
        # 22.3 versions before 22.3R2-EVO, 22.3R3-EVO
        '22.3R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if both NETCONF and gRPC are enabled
    netconf_config = commands.show_config_netconf
    grpc_config = commands.show_config_grpc

    netconf_enabled = 'system services netconf' in netconf_config
    grpc_enabled = 'system services extension-service request-response grpc' in grpc_config

    # Device is vulnerable if both services are enabled
    is_vulnerable = netconf_enabled and grpc_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21614. "
        "The device is running a vulnerable version with both NETCONF and gRPC enabled. "
        "This configuration can allow an attacker to cause rpd crash through specific DREND queries. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 22.2R2-S2, 22.2R3, 22.3R2, 22.3R3, 22.4R1, or later; "
        "Junos OS Evolved: 22.2R2-S2-EVO, 22.2R3-EVO, 22.3R2-EVO, 22.3R3-EVO, 22.4R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75755"
    )
