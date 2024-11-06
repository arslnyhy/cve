from comfy import medium

@medium(
    name='rule_cve202421617',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_nsr='show configuration | display set | match "routing-options nonstop-routing"',
        show_memory='show system memory | no-more',
        show_re='show chassis routing-engine no-forwarding'
    )
)
def rule_cve202421617(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21617 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an adjacent, unauthenticated attacker to cause memory leak
    leading to Denial of Service (DoS) when BGP flaps occur on NSR-enabled devices.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series (not affected as NSR is not supported)
    if 'SRX' in commands.show_version:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions before 21.2R3-S5
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2',
        '21.2R3-S3', '21.2R3-S4',
        # 21.3 versions before 21.3R3-S4
        '21.3R1', '21.3R2', '21.3R3', '21.3R3-S1', '21.3R3-S2',
        '21.3R3-S3',
        # 21.4 versions before 21.4R3-S4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2',
        '21.4R3-S3',
        # 22.1 versions before 22.1R3-S2
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1',
        # 22.2 versions before 22.2R3-S2
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1',
        # 22.3 versions before 22.3R2-S1, 22.3R3
        '22.3R1', '22.3R2',
        # 22.4 versions before 22.4R1-S2, 22.4R2
        '22.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if NSR is enabled
    nsr_config = commands.show_config_nsr
    nsr_enabled = 'routing-options nonstop-routing' in nsr_config

    if not nsr_enabled:
        return

    # Check for memory leak indicators
    memory_output = commands.show_memory
    re_output = commands.show_re

    # Look for high memory utilization or memory allocation failures
    high_memory = any(indicator in memory_output.lower() for indicator in [
        'allocation failed',
        'out of memory',
        'memory exhausted'
    ])

    # Look for RE memory pressure indicators
    re_pressure = any(indicator in re_output.lower() for indicator in [
        'memory utilization',
        'memory threshold exceeded'
    ])

    # Device shows signs of memory leak if either indicator is present
    memory_leak_signs = high_memory or re_pressure

    assert not memory_leak_signs, (
        f"Device {device.name} is vulnerable to CVE-2024-21617. "
        "The device is running a vulnerable version with NSR enabled and showing signs "
        "of memory leak. This can lead to DoS when BGP sessions flap. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S5, 21.3R3-S4, 21.4R3-S4, 22.1R3-S2, 22.2R3-S2, 22.3R2-S1, "
        "22.3R3, 22.4R1-S2, 22.4R2, 23.2R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75758"
    )
