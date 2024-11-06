from comfy import high

@high(
    name='rule_cve202421598',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp"'
    )
)
def rule_cve202421598(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21598 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending a BGP update with a malformed tunnel encapsulation attribute TLV that causes rpd to crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # Versions before 20.4R1 are not affected
    if not any(ver in version_output for ver in ['20.4R1', '20.4R1-EVO']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 20.4 versions after 20.4R1 and before 20.4R3-S9
        '20.4R1', '20.4R2', '20.4R3', '20.4R3-S1', '20.4R3-S2', '20.4R3-S3',
        '20.4R3-S4', '20.4R3-S5', '20.4R3-S6', '20.4R3-S7', '20.4R3-S8',
        # 21.2 versions before 21.2R3-S7
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3',
        '21.2R3-S4', '21.2R3-S5', '21.2R3-S6',
        # 21.3 versions before 21.3R3-S5
        '21.3R1', '21.3R2', '21.3R3', '21.3R3-S1', '21.3R3-S2', '21.3R3-S3', '21.3R3-S4',
        # 21.4 versions before 21.4R3-S5
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4',
        # 22.1 versions before 22.1R3-S4
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3',
        # 22.2 versions before 22.2R3-S3
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2',
        # 22.3 versions before 22.3R3-S1
        '22.3R1', '22.3R2', '22.3R3',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R1-S2
        '23.2R1', '23.2R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config = commands.show_config_bgp
    bgp_enabled = 'protocols bgp' in bgp_config

    assert not bgp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21598. "
        "The device is running a vulnerable version with BGP enabled. "
        "This configuration can allow an attacker to cause rpd crash through malformed BGP updates. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, "
        "22.3R3-S1, 22.4R3, 23.2R1-S2, 23.2R2, 23.4R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see http://supportportal.juniper.net/JSA75739"
    )
