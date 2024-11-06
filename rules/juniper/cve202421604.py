from comfy import high

@high(
    name='rule_cve202421604',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_filter='show configuration | display set | match "firewall filter lo0"'
    )
)
def rule_cve202421604(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21604 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending a high rate of specific packets that cause RE connectivity loss and system outage.
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S7-EVO versions
        '20.4R3-S6-EVO', '20.4R3-S5-EVO', '20.4R3-S4-EVO', '20.4R3-S3-EVO',
        '20.4R3-S2-EVO', '20.4R3-S1-EVO', '20.4R3-EVO', '20.4R2-EVO', '20.4R1-EVO',
        # 21.2 versions
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO',
        # 21.4 versions before 21.4R3-S5-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO', '21.4R3-S4-EVO',
        # 22.1 versions before 22.1R3-S2-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO',
        '22.1R3-S1-EVO',
        # 22.2 versions before 22.2R3-EVO
        '22.2R1-EVO', '22.2R2-EVO',
        # 22.3 versions before 22.3R2-EVO
        '22.3R1-EVO',
        # 22.4 versions before 22.4R2-EVO
        '22.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if lo0 firewall filter is configured
    filter_config = commands.show_config_filter
    filter_configured = 'firewall filter lo0' in filter_config

    assert filter_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-21604. "
        "The device is running a vulnerable version of Junos OS Evolved without a lo0 firewall filter. "
        "This configuration can allow an attacker to cause a complete system outage by sending "
        "a high rate of specific packets to the RE. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S7-EVO, 21.4R3-S5-EVO, 22.1R3-S2-EVO, 22.2R3-EVO, 22.3R2-EVO, "
        "22.4R2-EVO, 23.2R1-EVO, or later. "
        "As a workaround, configure a lo0 firewall filter to block unexpected and throttle expected traffic. "
        "For more information, see https://supportportal.juniper.net/JSA75745"
    )
