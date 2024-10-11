@high(
    name='rule_cve202420314',
    platform=['cisco_xe'],
    commands=dict(show_sd_access_fabric='show sd-access fabric edge-nodes'),
)
def rule_cve202420314(configuration, commands, device, devices):
    """
    This rule checks for the presence of the SD-Access fabric edge node configuration
    on Cisco IOS XE devices. Devices configured as SD-Access fabric edge nodes are
    vulnerable to the CVE-2024-20314 denial of service vulnerability.
    """

    # Retrieve the output of the 'show sd-access fabric edge-nodes' command
    sd_access_fabric_output = commands.show_sd_access_fabric

    # Check if the device is configured as an SD-Access fabric edge node
    # If the output contains information indicating edge node configuration, it is vulnerable
    is_edge_node = 'Edge Node' in sd_access_fabric_output

    # Assert that the device is not configured as an SD-Access fabric edge node
    # If it is, the rule will fail, indicating a potential vulnerability
    assert not is_edge_node, (
        f"Device {device.name} is configured as an SD-Access fabric edge node, "
        "which is vulnerable to CVE-2024-20314. Please update the software to a fixed version."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-sda-edge-dos-qZWuWXWG"
    )
