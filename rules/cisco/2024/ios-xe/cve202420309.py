from comfy import medium

@medium(
    name='rule_cve202420309',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_aux_config='show running-config | section line aux 0'
    ),
)
def rule_cve202420309(configuration, commands, device, devices):
    """
    This rule checks for a specific vulnerability in Cisco IOS XE devices related to the AUX port.
    The vulnerability can cause a denial of service if the AUX port is configured with flowcontrol hardware
    and allows reverse telnet connections (transport input all or telnet).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 3.x versions
        '3.2.0SE', '3.2.1SE', '3.2.2SE', '3.2.3SE',
        '3.3.0SE', '3.3.1SE', '3.3.2SE', '3.3.3SE', '3.3.4SE', '3.3.5SE',
        '3.3.0SQ', '3.3.1SQ',
        '3.4.0SQ', '3.4.1SQ',
        '3.5.0SQ', '3.5.1SQ', '3.5.2SQ', '3.5.3SQ', '3.5.4SQ', '3.5.5SQ', '3.5.6SQ', '3.5.7SQ', '3.5.8SQ',
        '3.6.2aE', '3.6.2E', '3.6.5bE', '3.6.7bE', '3.6.9E', '3.6.10E',
        '3.7.0S', '3.7.1S', '3.7.2S', '3.7.3S', '3.7.4S', '3.7.5S', '3.7.6S', '3.7.7S',
        '3.7.4aS', '3.7.2tS', '3.7.0bS', '3.7.1aS',
        '3.8.0S', '3.8.1S', '3.8.2S',
        '3.9.0S', '3.9.1S', '3.9.2S', '3.9.1aS', '3.9.0aS',
        '3.10.0S', '3.10.1S', '3.10.2S', '3.10.3S', '3.10.4S', '3.10.5S', '3.10.6S',
        '3.10.2tS', '3.10.7S', '3.10.1xbS', '3.10.8S', '3.10.8aS', '3.10.9S', '3.10.10S',
        '3.11.0S', '3.11.1S', '3.11.2S', '3.11.3S', '3.11.4S',
        '3.12.0S', '3.12.1S', '3.12.2S', '3.12.3S', '3.12.0aS', '3.12.4S',
        '3.13.0S', '3.13.1S', '3.13.2S', '3.13.3S', '3.13.4S', '3.13.5S',
        '3.13.2aS', '3.13.0aS', '3.13.5aS', '3.13.6S', '3.13.7S', '3.13.6aS', '3.13.7aS',
        '3.13.8S', '3.13.9S', '3.13.10S',
        '3.14.0S', '3.14.1S', '3.14.2S', '3.14.3S', '3.14.4S',
        '3.15.0S', '3.15.1S', '3.15.2S', '3.15.1cS', '3.15.3S', '3.15.4S',
        '3.16.0S', '3.16.1S', '3.16.1aS', '3.16.2S', '3.16.2aS', '3.16.0cS', '3.16.3S',
        '3.16.2bS', '3.16.3aS', '3.16.4S', '3.16.4aS', '3.16.4bS', '3.16.5S', '3.16.4dS',
        '3.16.6S', '3.16.7S', '3.16.6bS', '3.16.7aS', '3.16.7bS', '3.16.8S', '3.16.9S', '3.16.10S',
        '3.17.0S', '3.17.1S', '3.17.2S', '3.17.1aS', '3.17.3S', '3.17.4S',
        '3.18.0aS', '3.18.0S', '3.18.1S', '3.18.2S', '3.18.3S', '3.18.4S',
        '3.18.0SP', '3.18.1SP', '3.18.1aSP', '3.18.1bSP', '3.18.1cSP', '3.18.2SP',
        '3.18.2aSP', '3.18.3SP', '3.18.4SP', '3.18.3aSP', '3.18.3bSP', '3.18.5SP',
        '3.18.6SP', '3.18.7SP', '3.18.8aSP', '3.18.9SP',
        # 16.x versions
        '16.1.1', '16.1.2', '16.1.3',
        '16.2.1', '16.2.2',
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b',
        '16.3.6', '16.3.7', '16.3.8', '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a',
        '16.6.6', '16.6.7', '16.6.8', '16.6.9', '16.6.10',
        '16.7.1', '16.7.1a', '16.7.1b', '16.7.2', '16.7.3', '16.7.4',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.1d', '16.8.2',
        '16.8.1e', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4',
        '16.9.3a', '16.9.5', '16.9.5f', '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1c', '16.10.1e',
        '16.10.1d', '16.10.2', '16.10.1f', '16.10.1g', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.1w', '16.12.2',
        '16.12.1y', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s', '16.12.1x',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5',
        '16.12.6', '16.12.1z1', '16.12.5a', '16.12.5b', '16.12.1z2', '16.12.6a',
        '16.12.7', '16.12.9', '16.12.10', '16.12.10a',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x',
        '17.3.1z', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c',
        '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.6', '17.6.6a',
        '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.4', '17.9.1y1', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1w', '17.12.1a', '17.12.2', '17.12.2a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

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
        "The device is running a vulnerable version AND has AUX port configured with flowcontrol hardware and allows telnet connections. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aux-333WBz8f"
    )
