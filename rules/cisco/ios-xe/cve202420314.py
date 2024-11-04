from comfy import high

@high(
    name='rule_cve202420314',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_sd_access_fabric='show sd-access fabric edge-nodes'
    ),
)
def rule_cve202420314(configuration, commands, device, devices):
    """
    This rule checks for the presence of the SD-Access fabric edge node configuration
    on Cisco IOS XE devices. Devices configured as SD-Access fabric edge nodes and running
    a vulnerable version are vulnerable to the CVE-2024-20314 denial of service vulnerability.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 16.x versions
        '16.1.1', '16.1.2', '16.1.3',
        '16.2.1', '16.2.2',
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.1a', '16.7.1b', '16.7.2', '16.7.3', '16.7.4',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.1d', '16.8.2', '16.8.1e', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1c', '16.10.1e', '16.10.1d', '16.10.2', '16.10.1f',
        '16.10.1g', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.1w', '16.12.2', '16.12.1y', '16.12.2a', '16.12.3',
        '16.12.8', '16.12.2s', '16.12.1x', '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5',
        '16.12.6', '16.12.1z1', '16.12.5a', '16.12.5b', '16.12.1z2', '16.12.6a', '16.12.7', '16.12.9', '16.12.10',
        '16.12.10a',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x', '17.3.1z', '17.3.4', '17.3.5',
        '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y', '17.6.1z', '17.6.3a', '17.6.4',
        '17.6.1z1', '17.6.5', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3', '17.9.2a', '17.9.1x1', '17.9.3a',
        '17.9.4', '17.9.1y1', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1w', '17.12.1a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Retrieve the output of the 'show sd-access fabric edge-nodes' command
    sd_access_fabric_output = commands.show_sd_access_fabric

    # Check if the device is configured as an SD-Access fabric edge node
    # If the output contains information indicating edge node configuration, it is vulnerable
    is_edge_node = 'Edge Node' in sd_access_fabric_output

    # Assert that the device is not configured as an SD-Access fabric edge node
    # If it is, the rule will fail, indicating a potential vulnerability
    assert not is_edge_node, (
        f"Device {device.name} is vulnerable to CVE-2024-20314. "
        "The device is running a vulnerable version AND is configured as an SD-Access fabric edge node. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sda-edge-dos-qZWuWXWG"
    )
