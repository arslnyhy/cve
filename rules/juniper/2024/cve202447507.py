from comfy import medium

@medium(
    name='rule_cve202447507',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp"'
    )
)
def rule_cve202447507(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47507 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause an integrity impact
    by sending BGP updates with ASN value of zero in aggregator attribute, which gets propagated to
    downstream devices.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version
    is_evolved = 'Evolved' in version_output

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1'
    ]

    # List of vulnerable software versions for Junos OS Evolved
    evo_vulnerable_versions = [
        # All versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.2 versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.4 versions before 22.4R3-EVO
        '22.4R2-EVO', '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    bgp_enabled = 'protocols bgp' in bgp_config

    assert not bgp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-47507. "
        "The device is running a vulnerable version with BGP enabled. "
        "This configuration can allow an attacker to cause integrity impact by sending "
        "BGP updates with ASN value of zero in aggregator attribute. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3-S6, 22.1R3-S6, 22.2R3-S3, 22.4R3, 23.2R1, or later; "
        "Junos OS Evolved: 21.4R3-S7-EVO, 22.2R3-S4-EVO, 22.4R3-EVO, 23.2R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88138"
    )
