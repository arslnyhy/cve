from comfy import high

@high(
    name='rule_cve202439563',
    platform=['juniper_space'],
    commands=dict(
        show_version='show version',
        show_config_web='show configuration | display set | match "system services web-management"',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address"'
    )
)
def rule_cve202439563(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39563 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an unauthenticated, network-based attacker to execute arbitrary
    shell commands through a specially crafted GET request to the web application, leading
    to remote command execution with root privileges.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos Space
    version_output = commands.show_version
    if 'Junos Space' not in version_output:
        return

    # Check if web management is enabled
    web_config = commands.show_config_web
    web_enabled = 'system services web-management' in web_config

    if not web_enabled:
        return

    # Check if firewall filter is configured to limit web access
    filter_config = commands.show_config_filter
    filter_configured = 'web-management' in filter_config
    
    assert not filter_configured, (
        f"Device {device.name} is vulnerable to CVE-2024-39563. "
        "The device is running Junos Space 24.1R1 with web management enabled "
        "but without firewall filters limiting access to trusted hosts. "
        "This configuration allows unauthenticated attackers to execute arbitrary "
        "shell commands through specially crafted GET requests. "
        "Please upgrade to Junos Space 24.1R1 Patch V1 or later. "
        "As a workaround, configure firewall filters to limit web access to trusted hosts. "
        "For more information, see https://supportportal.juniper.net/JSA88110"
    )
