@high(
    name='rule_cve202420321',
    platform=['cisco_nxos'],
    commands=dict(
        show_bgp='show running-config | include "router bgp"',
        show_neighbors='show running-config | include "neighbor"'
    ),
)
def rule_cve202420321(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco NX-OS devices
    related to eBGP configuration that could lead to a Denial of Service (DoS)
    condition. The vulnerability is identified by CVE-2024-20321 and affects
    specific Cisco Nexus models when eBGP is configured with a neighbor from a
    different Autonomous System (AS).

    The rule verifies if the BGP feature is enabled and if there is at least
    one eBGP neighbor configured, which would make the device susceptible to
    the described vulnerability.
    """

    # Check if the device is one of the affected models
    affected_models = [
        'N3K-C36180YC-R', 'N3K-C3636C-R', 'N9K-X9624D-R2', 'N9K-X9636C-R',
        'N9K-X9636C-RX', 'N9K-X9636Q-R', 'N9K-X96136YC-R'
    ]
    
    # If the device model is not in the affected list, skip the test
    if device.platform not in affected_models:
        return

    # Check if BGP is configured on the device
    bgp_config = commands.show_bgp
    assert 'router bgp' in bgp_config, "BGP is not configured on this device."

    # Check if there is any eBGP neighbor configured
    neighbors_config = commands.show_neighbors
    has_ebgp_neighbor = any('remote-as' in line for line in neighbors_config.splitlines())
    assert has_ebgp_neighbor, "No eBGP neighbor is configured."

    # If both conditions are met, the device is vulnerable
    # Raise an assertion error to indicate the vulnerability
    assert False, (
        f"Device {device.name} with IP {device.ip_address} is vulnerable to "
        "CVE-2024-20321. eBGP is configured with a neighbor from a different AS."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ebgp-dos-L3QCwVJ"
    )
