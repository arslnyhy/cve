from comfy import high

@high(
    name='rule_cve202447499',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bmp='show configuration | display set | match "protocols bgp.*bmp route-monitoring pre-policy|routing-options bmp.*route-monitoring pre-policy"',
        show_config_exclude='show configuration | display set | match "exclude-non-feasible"'
    )
)
def rule_cve202447499(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47499 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending BGP updates with malformed AS PATH attributes when BMP pre-policy monitoring is enabled.

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
        # All versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S8
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S2
        '22.4R3-S1', '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S1
        '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R1-S2, 23.4R2
        '23.4R1', '23.4R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in junos_vulnerable_versions]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BMP pre-policy monitoring is configured
    bmp_config = commands.show_config_bmp
    bmp_enabled = any(policy in bmp_config for policy in [
        'protocols bgp bmp route-monitoring pre-policy',
        'routing-options bmp route-monitoring pre-policy'
    ])

    if not bmp_enabled:
        return

    # Check if workaround is configured
    exclude_config = commands.show_config_exclude
    workaround_configured = 'exclude-non-feasible' in exclude_config

    assert workaround_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-47499. "
        "The device is running a vulnerable version with BMP pre-policy monitoring enabled "
        "but without the exclude-non-feasible workaround configured. This can allow an attacker "
        "to cause RPD crash through malformed AS PATH attributes in BGP updates. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S8, 21.4R3-S8, 22.2R3-S4, 22.3R3-S3, 22.4R3-S2, 23.2R2-S1, "
        "23.4R1-S2, 23.4R2, 24.2R1, or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, configure: set protocols bgp bmp route-monitoring pre-policy exclude-non-feasible "
        "or set routing-options bmp route-monitoring pre-policy exclude-non-feasible. "
        "For more information, see https://supportportal.juniper.net/JSA88129"
    )
