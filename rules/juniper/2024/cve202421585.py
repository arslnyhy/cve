from comfy import medium

@medium(
    name='rule_cve202421585',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_nsr='show configuration | display set | match "chassis redundancy graceful-switchover|routing-options nonstop-routing"',
        show_config_gr='show configuration | display set | match "protocols bgp graceful-restart"'
    )
)
def rule_cve202421585(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21585 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a DoS condition
    by causing the routing protocol daemon (rpd) process to crash and restart when BGP sessions flap
    on NSR-enabled devices with GR helper mode.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series (not affected)
    if 'SRX' in commands.show_version:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1', '21.3R3',
        '21.3R2', '21.3R1',
        # 21.4 versions
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1', '21.4R3',
        '21.4R2', '21.4R1',
        # 22.1 versions
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions
        '22.4R2-S1', '22.4R2', '22.4R1',
        # 23.2 versions
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if NSR is enabled
    nsr_config = commands.show_config_nsr
    nsr_enabled = all(config in nsr_config for config in [
        'chassis redundancy graceful-switchover',
        'routing-options nonstop-routing'
    ])

    # Check if GR helper mode is enabled (enabled by default unless explicitly disabled)
    gr_config = commands.show_config_gr
    gr_disabled = 'protocols bgp graceful-restart disable' in gr_config

    # Device is vulnerable if NSR is enabled and GR helper mode is not disabled
    is_vulnerable = nsr_enabled and not gr_disabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21585. "
        "The device is running a vulnerable version with NSR enabled and GR helper mode not disabled. "
        "This configuration can lead to rpd process crash when BGP sessions flap. "
        "Please upgrade to a fixed version or disable GR helper mode. "
        "For more information, see https://supportportal.juniper.net/JSA75723"
    )
