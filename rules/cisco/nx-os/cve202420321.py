from comfy import high

@high(
    name='rule_cve202420321',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_bgp='show running-config | include "router bgp"',
        show_neighbors='show running-config | include neighbor'
    ),
)
def rule_cve202420321(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco NX-OS devices
    related to eBGP configuration that could lead to a Denial of Service (DoS)
    condition. The vulnerability is identified by CVE-2024-20321 and affects
    specific Cisco Nexus models when eBGP is configured with a neighbor from a
    different Autonomous System (AS).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 7.0(3) versions
        '7.0(3)F1(1)', '7.0(3)F2(1)', '7.0(3)F2(2)', '7.0(3)F3(1)', '7.0(3)F3(2)',
        '7.0(3)F3(3)', '7.0(3)F3(3a)', '7.0(3)F3(3c)', '7.0(3)F3(4)', '7.0(3)F3(5)',
        # 9.2 versions
        '9.2(1)', '9.2(2)', '9.2(2t)', '9.2(3)', '9.2(4)', '9.2(2v)',
        # 9.3 versions
        '9.3(1)', '9.3(2)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(7)', '9.3(7a)',
        '9.3(8)', '9.3(9)', '9.3(10)', '9.3(11)', '9.3(12)',
        # 10.1 versions
        '10.1(1)', '10.1(2)', '10.1(2t)',
        # 10.2 versions
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(3)', '10.2(3t)', '10.2(4)', '10.2(5)',
        '10.2(3v)', '10.2(6)',
        # 10.3 versions
        '10.3(1)', '10.3(2)', '10.3(3)', '10.3(99w)', '10.3(99x)', '10.3(4a)',
        # 10.4 versions
        '10.4(1)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if BGP is configured on the device
    bgp_enabled = 'router bgp' in commands.show_bgp

    # Check if there is any eBGP neighbor configured
    has_ebgp_neighbor = 'remote-as' in commands.show_neighbors

    # If both conditions are met, the device is vulnerable
    # Raise an assertion error to indicate the vulnerability
    assert not (bgp_enabled and has_ebgp_neighbor), (
        f"Device {device.name} is vulnerable to CVE-2024-20321. "
        "The device is running a vulnerable version AND has eBGP configured with a neighbor from a different AS. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ebgp-dos-L3QCwVJ"
    )
