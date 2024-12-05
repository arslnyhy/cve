from comfy import high

@high(
    name='rule_cve202421612',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_ofp_status='show system connections | match ofp | match LISTEN',
        show_config_filter='show configuration | display set | match "firewall family inet filter mgmt-filter"'
    )
)
def rule_cve202421612(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21612 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending specific TCP packets that cause OFP crash and RE restart.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.2R3-S7-EVO versions
        '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO', '21.2R3-S3-EVO',
        '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO', '21.2R2-EVO', '21.2R1-EVO',
        # 21.3 versions before 21.3R3-S5-EVO
        '21.3R3-S4-EVO', '21.3R3-S3-EVO', '21.3R3-S2-EVO', '21.3R3-S1-EVO',
        '21.3R3-EVO', '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-S5-EVO
        '21.4R3-S4-EVO', '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S4-EVO
        '22.1R3-S3-EVO', '22.1R3-S2-EVO', '22.1R3-S1-EVO',
        '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-EVO
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R2-EVO, 22.4R3-EVO
        '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if OFP is running and listening
    ofp_output = commands.show_ofp_status
    ofp_enabled = 'LISTEN' in ofp_output

    if not ofp_enabled:
        return

    # Check if firewall filter is configured for OFP protection
    filter_config = commands.show_config_filter
    required_config = [
        'firewall family inet filter mgmt-filter term discard_ofp from protocol tcp',
        'firewall family inet filter mgmt-filter term discard_ofp then discard',
        'firewall family inet filter mgmt-filter term 2 then accept'
    ]
    filter_configured = all(config in filter_config for config in required_config)

    assert filter_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-21612. "
        "The device is running a vulnerable version of Junos OS Evolved with OFP enabled "
        "but without proper firewall filter protection. This can allow an attacker to cause "
        "OFP crash and RE restart through specific TCP packets. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S7-EVO, 21.3R3-S5-EVO, 21.4R3-S5-EVO, 22.1R3-S4-EVO, 22.2R3-S3-EVO, "
        "22.3R3-EVO, 22.4R2-EVO, 22.4R3-EVO, 23.2R1-EVO, or later. "
        "As a workaround, configure firewall filter to protect OFP ports. "
        "For more information, see https://supportportal.juniper.net/JSA75753"
    )
