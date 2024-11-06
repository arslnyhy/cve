from comfy import medium

@medium(
    name='rule_cve202439535',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_vpls='show configuration | display set | match "routing-instances.*instance-type vpls"',
        show_config_irb='show configuration | display set | match "(routing-interface irb|family inet)"'
    )
)
def rule_cve202439535(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39535 vulnerability in Juniper Networks Junos OS Evolved on ACX 7000 Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS) by
    sending specific traffic to a VPLS instance with Layer 3 or IRB interface, causing evo-pfemand crashes.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is ACX 7000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['ACX7024', 'ACX7100', 'ACX7509']):
        return

    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        '22.4R2-S1-EVO',
        '22.4R2-S2-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if VPLS is configured
    vpls_config = commands.show_config_vpls
    vpls_enabled = 'instance-type vpls' in vpls_config

    if not vpls_enabled:
        return

    # Check for Layer 3 or IRB interface in VPLS
    irb_config = commands.show_config_irb
    has_l3_interface = any([
        'routing-interface irb' in irb_config,  # IRB interface
        'family inet' in irb_config  # Layer 3 interface
    ])

    assert not has_l3_interface, (
        f"Device {device.name} is vulnerable to CVE-2024-39535. "
        "The device is running a vulnerable version of Junos OS Evolved with VPLS and Layer 3/IRB "
        "interfaces configured. This can allow an attacker to cause evo-pfemand crashes through "
        "specific traffic. "
        "Please upgrade to version 22.4R3-EVO or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA82995"
    )
