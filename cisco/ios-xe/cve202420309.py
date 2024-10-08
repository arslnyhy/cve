@medium(
    name='rule_cve202420309',
    platform=['cisco_ios'],
    commands=dict(show_aux_config='show running-config | section line aux 0'),
)
def rule_cve202420309(configuration, commands, device, devices):
    """
    This rule checks for a specific vulnerability in Cisco IOS XE devices related to the AUX port.
    The vulnerability can cause a denial of service if the AUX port is configured with flowcontrol hardware
    and allows reverse telnet connections (transport input all or telnet).
    """

    # Extract the configuration for the AUX port from the command output
    aux_config = commands.show_aux_config

    # Check if 'flowcontrol hardware' is enabled on the AUX port
    flowcontrol_enabled = 'flowcontrol hardware' in aux_config

    # Check if 'transport input all' or 'transport input telnet' is configured
    transport_input_all = 'transport input all' in aux_config
    transport_input_telnet = 'transport input telnet' in aux_config

    # If both flowcontrol is enabled and transport input allows telnet, the device is vulnerable
    is_vulnerable = flowcontrol_enabled and (transport_input_all or transport_input_telnet)

    # Assert that the device is not vulnerable
    # If the device is vulnerable, this assertion will fail, indicating a problem
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20309. "
        "AUX port is configured with flowcontrol hardware and allows telnet connections."
    )
