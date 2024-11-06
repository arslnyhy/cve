from comfy import high

@high(
    name='rule_cve202447502',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_system_connections='show system connections',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address"'
    )
)
def rule_cve202447502(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47502 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by establishing TCP sessions that leave stale state entries, leading to resource exhaustion.

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
        # All versions before 21.4R3-S9-EVO
        '21.4R3-S8-EVO', '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO',
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2 versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.4 versions before 22.4R3-S3-EVO
        '22.4R3-S2-EVO', '22.4R3-S1-EVO', '22.4R3-EVO',
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R2-S1-EVO
        '23.2R2-EVO', '23.2R1-EVO',
        # 23.4 versions before 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for firewall filter protecting control plane access
    filter_config = commands.show_config_filter
    filter_configured = 'firewall filter' in filter_config and 'source-address' in filter_config

    if not filter_configured:
        # Check for signs of TCP session state accumulation
        connections = commands.show_system_connections
        connection_lines = connections.splitlines()
        
        # Count total and CLOSED/TIME_WAIT connections
        total_connections = len(connection_lines)
        stale_connections = len([line for line in connection_lines 
                               if 'CLOSED' in line or 'TIME_WAIT' in line])
        
        # Alert if more than 50% of connections are in CLOSED/TIME_WAIT state
        high_stale_ratio = stale_connections > (total_connections * 0.5)

        assert not high_stale_ratio, (
            f"Device {device.name} is vulnerable to CVE-2024-47502. "
            "The device is running a vulnerable version of Junos OS Evolved without firewall filters "
            f"and showing signs of TCP session state accumulation ({stale_connections}/{total_connections} stale connections). "
            "This can lead to control plane resource exhaustion and connection failures. "
            "Please upgrade to one of the following fixed versions: "
            "21.4R3-S9-EVO, 22.2R3-S4-EVO, 22.4R3-S3-EVO, 23.2R2-S1-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
            "As a workaround, configure firewall filters to limit access to trusted sources. "
            "For more information, see https://supportportal.juniper.net/JSA88132"
        )
