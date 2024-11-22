from comfy import high

@high(
    name='rule_cve202447491',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_version_detail='show version detail',
        show_bgp_config='show configuration | display set | match "protocols bgp"'
    ),
)
def rule_cve202447491(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47491 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS condition
    by sending malformed BGP UPDATE packets that crash the routing protocol daemon (rpd).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.4R3', '22.4R3-S1', '22.4R3-S2',
        '23.2R1', '23.2R2',
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_bgp_config
    bgp_configured = 'protocols bgp' in bgp_config

    if not bgp_configured:
        return

    # Check if system is 32-bit (more vulnerable) or 64-bit (less vulnerable)
    version_detail = commands.show_version_detail
    is_32bit = '32-bit' in version_detail

    # Assert that the device is not vulnerable
    # Note: 64-bit systems are technically vulnerable but with extremely low probability
    assert not (bgp_configured and is_32bit), (
        f"Device {device.name} is vulnerable to CVE-2024-47491. "
        "The device is running a vulnerable version on 32-bit hardware with BGP configured, "
        "which makes it susceptible to DoS attacks through malformed BGP UPDATE packets. "
        "For more information, see https://supportportal.juniper.net/JSA88116"
    )
