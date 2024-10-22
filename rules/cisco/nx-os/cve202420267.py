from comfy import high

@high(
    name='rule_cve202420267',
    platform=['cisco_nxos'],
    commands=dict(show_mpls_interface_detail='show mpls interface detail'),
)
def rule_cve202420267(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20267 vulnerability in Cisco NX-OS devices.
    The vulnerability allows an unauthenticated, remote attacker to cause a denial of service (DoS)
    by sending a crafted IPv6 packet encapsulated within an MPLS frame to an MPLS-enabled interface.
    The test verifies if MPLS is configured on the device, which is a condition for the vulnerability.
    """

    # Extract the output of the 'show mpls interface detail' command
    mpls_output = commands.show_mpls_interface_detail

    # Check if the output contains 'MPLS operational', indicating MPLS is configured
    is_mpls_configured = 'MPLS operational' in mpls_output

    # Assert that MPLS is not configured to pass the test (no vulnerability exposure)
    # If MPLS is configured, the test will fail, indicating potential vulnerability exposure
    assert not is_mpls_configured, (
        f"Device {device.name} with IP {device.ip_address} is potentially vulnerable to CVE-2024-20267. "
        "MPLS is configured and operational on this device."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-mpls-dos-R9ycXkwM"
    )
