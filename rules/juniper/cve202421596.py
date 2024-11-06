from comfy import medium

@medium(
    name='rule_cve202421596',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bgp='show configuration | display set | match "protocols bgp"',
        show_config_nsr='show configuration | display set | match "routing-options nonstop-routing"'
    )
)
def rule_cve202421596(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21596 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending specific BGP UPDATE messages that cause RPD crash in the backup RE when NSR is enabled.

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
        # Pre-20.4R3-S9 versions
        '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5', '20.4R3-S4',
        '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2-S2
        '22.4R2-S1', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if BGP and NSR are configured
    bgp_config = commands.show_config_bgp
    nsr_config = commands.show_config_nsr
    
    bgp_enabled = 'protocols bgp' in bgp_config
    nsr_enabled = 'routing-options nonstop-routing' in nsr_config

    # Device is vulnerable if both BGP and NSR are enabled
    is_vulnerable = bgp_enabled and nsr_enabled

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21596. "
        "The device is running a vulnerable version with both BGP and NSR enabled. "
        "This configuration can allow an attacker to cause RPD crash in backup RE through BGP UPDATE messages. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9, 21.2R3-S7, 21.3R3-S5, 21.4R3-S5, 22.1R3-S4, 22.2R3-S2, 22.3R3-S1, "
        "22.4R2-S2, 22.4R3, 23.2R1-S2, 23.2R2, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75735"
    )
