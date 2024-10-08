@medium(
    name='rule_cve202420390',
    platform=['cisco_iosxr'],
    commands=dict(show_xml_config='show running-config | include xml'),
)
def rule_cve202420390(configuration, commands, device, devices):
    """
    This rule checks for the presence of the Dedicated XML Agent feature in the
    running configuration of Cisco IOS XR devices. The presence of this feature
    indicates a vulnerability to CVE-2024-20390, which can lead to a denial of
    service on XML TCP listen port 38751.

    The test involves executing the 'show running-config | include xml' command
    and checking if 'xml agent' is present in the output. If found, the device
    is considered vulnerable.
    """

    # Retrieve the output of the 'show running-config | include xml' command
    xml_config_output = commands.show_xml_config

    # Check if 'xml agent' is present in the command output
    # If 'xml agent' is found, the device is vulnerable
    assert 'xml agent' not in xml_config_output, (
        f"Device {device.name} is vulnerable to CVE-2024-20390. "
        "The Dedicated XML Agent feature is enabled."
    )
