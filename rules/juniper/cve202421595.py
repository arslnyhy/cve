from comfy import high

@high(
    name='rule_cve202421595',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_vxlan_config='show configuration | display set | match "vxlan"'
    ),
)
def rule_cve202421595(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-21595 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS)
    if the device is configured for VXLAN and running a vulnerable version.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '22.1R3', '22.1R3-S1', '22.1R3-S2',
        '22.2R2', '22.2R2-S1', '22.2R2-S2',
        '22.3', '22.3R1', '22.3R2', '22.3R2-S1',
        '22.4', '22.4R1',
        '23.1', '23.1R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Extract the VXLAN configuration from the command output
    vxlan_config = commands.show_vxlan_config

    # Check if VXLAN is configured
    vxlan_configured = 'vxlan' in vxlan_config

    # Assert that the device is not vulnerable
    assert not vxlan_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-21595. "
        "The device is running a vulnerable version and is configured for VXLAN, "
        "which makes it susceptible to DoS attacks. "
        "For more information, see https://advisory.juniper.net/JSA75734"
    )
