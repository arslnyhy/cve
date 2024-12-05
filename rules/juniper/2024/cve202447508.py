from comfy import high

@high(
    name='rule_cve202447505',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_snmp_config='show configuration | display set | match "snmp"',
        show_guids='show platform application-info allocations app evo-pfemand/evo-pfemand'
    ),
)
def rule_cve202447505(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47505 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an authenticated attacker to cause a DoS condition through
    GUID resource leaks in the PFE management daemon when executing specific CLI commands or SNMP GET operations.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6',
        '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3', '22.1R3-S4', '22.1R3-S5',
        '22.2R3', '22.2R3-S1', '22.2R3-S2',
        '22.3R3', '22.3R3-S1', '22.3R3-S2',
        '22.4R2', '22.4R2-S1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if SNMP is configured with read access
    snmp_config = commands.show_snmp_config
    snmp_enabled = any(x in snmp_config for x in ['community', 'v3'])

    # Assert that the device is not vulnerable
    assert not snmp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-47505. "
        "The device is running a vulnerable version with SNMP read access enabled and showing signs of GUID resource leaks, "
        "which indicates potential exploitation through CLI commands or SNMP GET operations. "
        "For more information, see https://supportportal.juniper.net/JSA88136"
    )
