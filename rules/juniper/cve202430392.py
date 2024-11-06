from comfy import high

@high(
    name='rule_cve202430392',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_urlf='show configuration | display set | match "services url-filtering"',
        show_config_template='show configuration | display set | match "url-filter-template"'
    )
)
def rule_cve202430392(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30392 vulnerability in Juniper Networks Junos OS on MX Series
    with SPC3 and MS-MPC/-MIC. The vulnerability allows an unauthenticated, network-based attacker
    to cause a Denial of Service (DoS) by sending specific URL requests that cause flowd to crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with SPC3 and MS-MPC/-MIC
    chassis_output = commands.show_chassis_hardware
    if not ('MX' in chassis_output and 'SPC3' in chassis_output and 'MS-MPC' in chassis_output):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S3
        '22.1R3-S2', '22.1R3-S1', '22.1R3',
        '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S1
        '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2-S2, 22.3R3
        '22.3R2-S1', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R2-S1, 22.4R3
        '22.4R2', '22.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if URL filtering is enabled
    urlf_config = commands.show_config_urlf
    urlf_enabled = 'services url-filtering enable' in urlf_config

    if not urlf_enabled:
        return

    # Check if URL filter template is configured
    template_config = commands.show_config_template
    template_configured = all(keyword in template_config for keyword in [
        'url-filter-template',
        'client-interfaces',
        'server-interfaces',
        'dns-server',
        'url-filter-database'
    ])

    assert not template_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-30392. "
        "The device is running a vulnerable version with URL filtering enabled and template configured. "
        "This configuration can allow an attacker to cause flowd crashes through specific URL requests. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S6, 21.3R3-S5, 21.4R3-S5, 22.1R3-S3, 22.2R3-S1, 22.3R2-S2, 22.3R3, "
        "22.4R2-S1, 22.4R3, 23.2R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA79092"
    )
