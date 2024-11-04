from comfy import medium

@medium(
    name='rule_cve202420390',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_xml_config='show running-config | include xml'
    ),
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
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 6.5.x versions
        '6.5.1', '6.5.2', '6.5.3', '6.5.15', '6.5.25', '6.5.26', '6.5.28', '6.5.29',
        '6.5.31', '6.5.32', '6.5.33', '6.5.90', '6.5.92', '6.5.93',
        # 6.6.x versions
        '6.6.1', '6.6.2', '6.6.3', '6.6.4', '6.6.11', '6.6.12', '6.6.25',
        # 6.7.x versions
        '6.7.1', '6.7.2', '6.7.3', '6.7.4', '6.7.35',
        # 6.8.x versions
        '6.8.1', '6.8.2',
        # 6.9.x versions
        '6.9.1', '6.9.2',
        # 7.0.x versions
        '7.0.0', '7.0.1', '7.0.2', '7.0.11', '7.0.12', '7.0.14', '7.0.90',
        # 7.1.x versions
        '7.1.1', '7.1.2', '7.1.3', '7.1.15', '7.1.25',
        # 7.2.x versions
        '7.2.0', '7.2.1', '7.2.2', '7.2.12',
        # 7.3.x versions
        '7.3.1', '7.3.2', '7.3.3', '7.3.4', '7.3.5', '7.3.6', '7.3.15', '7.3.16', '7.3.27',
        # 7.4.x versions
        '7.4.1', '7.4.2', '7.4.15', '7.4.16',
        # 7.5.x versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5', '7.5.12', '7.5.52',
        # 7.6.x versions
        '7.6.1', '7.6.2', '7.6.3', '7.6.15',
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2', '7.8.12', '7.8.22',
        # 7.9.x versions
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1', '7.10.2',
        # 7.11.x versions
        '7.11.1', '7.11.2',
        # 24.x versions
        '24.1.1', '24.2.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Retrieve the output of the 'show running-config | include xml' command
    xml_config_output = commands.show_xml_config

    # Check if 'xml agent' is present in the command output
    # If 'xml agent' is found, the device is vulnerable
    assert 'xml agent' not in xml_config_output, (
        f"Device {device.name} is vulnerable to CVE-2024-20390. "
        "The device is running a vulnerable version AND has the Dedicated XML Agent feature enabled. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-xml-tcpdos-ZEXvrU2S"
    )
