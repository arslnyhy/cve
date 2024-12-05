from comfy import high

@high(
    name='rule_cve202420267',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_mpls_interface_detail='show mpls interface detail'
    ),
)
def rule_cve202420267(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20267 vulnerability in Cisco NX-OS devices.
    The vulnerability allows an unauthenticated, remote attacker to cause a denial of service (DoS)
    by sending a crafted IPv6 packet encapsulated within an MPLS frame to an MPLS-enabled interface.
    The test verifies if MPLS is configured on the device, which is a condition for the vulnerability.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 6.0(2) versions
        '6.0(2)A3(1)', '6.0(2)A3(2)', '6.0(2)A3(4)',
        '6.0(2)A4(1)', '6.0(2)A4(2)', '6.0(2)A4(3)', '6.0(2)A4(4)', '6.0(2)A4(5)', '6.0(2)A4(6)',
        '6.0(2)A6(1)', '6.0(2)A6(1a)', '6.0(2)A6(2)', '6.0(2)A6(2a)', '6.0(2)A6(3)', '6.0(2)A6(3a)',
        '6.0(2)A6(4)', '6.0(2)A6(4a)', '6.0(2)A6(5)', '6.0(2)A6(5a)', '6.0(2)A6(5b)', '6.0(2)A6(6)',
        '6.0(2)A6(7)', '6.0(2)A6(8)', '6.0(2)A7(1)', '6.0(2)A7(1a)', '6.0(2)A7(2)', '6.0(2)A7(2a)',
        '6.0(2)A8(1)', '6.0(2)A8(2)', '6.0(2)A8(3)', '6.0(2)A8(4)', '6.0(2)A8(4a)', '6.0(2)A8(5)',
        '6.0(2)A8(6)', '6.0(2)A8(7)', '6.0(2)A8(7a)', '6.0(2)A8(7b)', '6.0(2)A8(8)', '6.0(2)A8(9)',
        '6.0(2)A8(10)', '6.0(2)A8(10a)', '6.0(2)A8(11)', '6.0(2)A8(11a)', '6.0(2)A8(11b)',
        # 6.0(2)U versions
        '6.0(2)U2(1)', '6.0(2)U2(2)', '6.0(2)U2(3)', '6.0(2)U2(4)', '6.0(2)U2(5)', '6.0(2)U2(6)',
        '6.0(2)U3(1)', '6.0(2)U3(2)', '6.0(2)U3(3)', '6.0(2)U3(4)', '6.0(2)U3(5)', '6.0(2)U3(6)',
        '6.0(2)U3(7)', '6.0(2)U3(8)', '6.0(2)U3(9)', '6.0(2)U4(1)', '6.0(2)U4(2)', '6.0(2)U4(3)',
        '6.0(2)U4(4)', '6.0(2)U5(1)', '6.0(2)U5(2)', '6.0(2)U5(3)', '6.0(2)U5(4)', '6.0(2)U6(1)',
        '6.0(2)U6(2)', '6.0(2)U6(3)', '6.0(2)U6(4)', '6.0(2)U6(5)', '6.0(2)U6(6)', '6.0(2)U6(7)',
        '6.0(2)U6(8)', '6.0(2)U6(9)', '6.0(2)U6(10)', '6.0(2)U6(1a)', '6.0(2)U6(2a)', '6.0(2)U6(3a)',
        '6.0(2)U6(4a)', '6.0(2)U6(5a)', '6.0(2)U6(5b)', '6.0(2)U6(5c)',
        # 6.2 versions
        '6.2(2)', '6.2(2a)', '6.2(6)', '6.2(6a)', '6.2(6b)', '6.2(8)', '6.2(8a)', '6.2(8b)',
        '6.2(10)', '6.2(12)', '6.2(14)', '6.2(16)', '6.2(18)', '6.2(20)', '6.2(20a)',
        '6.2(22)', '6.2(24)', '6.2(24a)',
        # 7.0(3) versions
        '7.0(3)F1(1)', '7.0(3)F2(1)', '7.0(3)F2(2)', '7.0(3)F3(1)', '7.0(3)F3(2)',
        '7.0(3)F3(3)', '7.0(3)F3(3a)', '7.0(3)F3(3c)', '7.0(3)F3(4)', '7.0(3)F3(5)',
        '7.0(3)I2(1)', '7.0(3)I2(1a)', '7.0(3)I2(2)', '7.0(3)I2(2a)', '7.0(3)I2(2b)',
        '7.0(3)I2(2c)', '7.0(3)I2(2d)', '7.0(3)I2(2e)', '7.0(3)I2(3)', '7.0(3)I2(4)',
        '7.0(3)I2(5)', '7.0(3)I3(1)', '7.0(3)I4(1)', '7.0(3)I4(2)', '7.0(3)I4(3)',
        '7.0(3)I4(4)', '7.0(3)I4(5)', '7.0(3)I4(6)', '7.0(3)I4(7)', '7.0(3)I4(8)',
        '7.0(3)I4(8a)', '7.0(3)I4(8b)', '7.0(3)I4(8z)', '7.0(3)I4(9)', '7.0(3)I5(1)',
        '7.0(3)I5(2)', '7.0(3)I6(1)', '7.0(3)I6(2)', '7.0(3)I7(1)', '7.0(3)I7(2)',
        '7.0(3)I7(3)', '7.0(3)I7(4)', '7.0(3)I7(5)', '7.0(3)I7(5a)', '7.0(3)I7(6)',
        '7.0(3)I7(7)', '7.0(3)I7(8)', '7.0(3)I7(9)', '7.0(3)I7(10)',
        # 7.1 versions
        '7.1(0)N1(1)', '7.1(0)N1(1a)', '7.1(0)N1(1b)', '7.1(1)N1(1)', '7.1(2)N1(1)',
        '7.1(3)N1(1)', '7.1(3)N1(2)', '7.1(4)N1(1)', '7.1(5)N1(1)', '7.1(5)N1(1b)',
        # 7.2 and 7.3 versions
        '7.2(0)D1(1)', '7.2(1)D1(1)', '7.2(2)D1(1)', '7.2(2)D1(2)',
        '7.3(0)D1(1)', '7.3(0)DX(1)', '7.3(0)N1(1)',
        # 9.2 versions
        '9.2(1)', '9.2(2)', '9.2(2t)', '9.2(2v)', '9.2(3)', '9.2(4)',
        # 9.3 versions
        '9.3(1)', '9.3(2)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(7)', '9.3(7a)',
        '9.3(8)', '9.3(9)', '9.3(10)', '9.3(11)', '9.3(12)',
        # 10.1 versions
        '10.1(1)', '10.1(2)', '10.1(2t)',
        # 10.2 versions
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(3)', '10.2(3t)', '10.2(3v)',
        '10.2(4)', '10.2(5)', '10.2(6)',
        # 10.3 and 10.4 versions
        '10.3(1)', '10.3(2)', '10.3(3)', '10.3(99w)', '10.3(99x)',
        '10.4(1)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the 'show mpls interface detail' command
    mpls_output = commands.show_mpls_interface_detail

    # Check if the output contains 'MPLS operational', indicating MPLS is configured
    mpls_configured = 'MPLS operational' in mpls_output

    # Assert that MPLS is not configured if the version is vulnerable
    assert not mpls_configured, (
        f"Device {device.name} with IP {device.ip_address} is vulnerable to CVE-2024-20267. "
        "The device is running a vulnerable version AND has MPLS configured and operational. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv6-mpls-dos-R9ycXkwM"
    )
