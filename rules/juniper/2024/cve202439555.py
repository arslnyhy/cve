from comfy import high

@high(
    name='rule_cve202439555',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp.*segment-routing-te"',
        show_config_tolerance='show configuration | display set | match "protocols bgp bgp-error-tolerance"'
    )
)
def rule_cve202439555(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39555 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending malformed BGP update messages with tunnel encapsulation attributes that cause session reset
    when segment routing is enabled.

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
        # All versions before 21.4R3-S8
        '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3',
        '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S4
        '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S3
        '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S1
        '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R1-S2, 23.4R2
        '23.4R1', '23.4R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # All versions before 21.4R3-S8-EVO
        '21.4R3-S7-EVO', '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO',
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO',
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.2-EVO versions before 22.2R3-S4-EVO
        '22.2R3-S3-EVO', '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4-EVO versions before 22.4R3-S3-EVO
        '22.4R3-S2-EVO', '22.4R3-S1-EVO', '22.4R3-EVO',
        '22.4R2-EVO', '22.4R1-EVO',
        # 23.2-EVO versions before 23.2R2-S1-EVO
        '23.2R2-EVO', '23.2R1-EVO',
        # 23.4-EVO versions before 23.4R1-S2-EVO, 23.4R2-EVO
        '23.4R1-EVO', '23.4R1-S1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if is_evolved else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if segment routing is enabled in BGP
    bgp_config = commands.show_config_bgp
    sr_enabled = any(sr_type in bgp_config for sr_type in [
        'family inet segment-routing-te',
        'family inet6 segment-routing-te'
    ])

    if not sr_enabled:
        return

    # Check if BGP Error Tolerance is enabled (workaround)
    tolerance_config = commands.show_config_tolerance
    error_tolerance_enabled = 'protocols bgp bgp-error-tolerance' in tolerance_config

    assert error_tolerance_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-39555. "
        "The device is running a vulnerable version with BGP segment routing enabled "
        "but without BGP Error Tolerance configured. This can allow an attacker to cause "
        "BGP session resets through malformed tunnel encapsulation attributes. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3-S8, 22.2R3-S4, 22.3R3-S3, 22.4R3-S3, 23.2R2-S1, 23.4R1-S2, "
        "23.4R2, 24.2R1, or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "As a workaround, configure: set protocols bgp bgp-error-tolerance. "
        "For more information, see https://supportportal.juniper.net/JSA83015"
    )
