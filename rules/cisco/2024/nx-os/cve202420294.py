from comfy import medium

@medium(
    name='rule_cve202420294',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_feature='show feature | include lldp',
        show_lldp_interface='show lldp interface eth 1/1', # Change this interface according to the device
    ),
)
def rule_cve202420294(configuration, commands, device, devices):
    """
    This rule checks for the presence and status of the LLDP feature on Cisco FXOS and NX-OS devices.
    The vulnerability (CVE-2024-20294) allows an unauthenticated, adjacent attacker to cause
    a denial of service (DoS) condition by sending crafted LLDP packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 6.0(2)A versions
        '6.0(2)A3(1)', '6.0(2)A3(2)', '6.0(2)A3(4)', '6.0(2)A4(1)', '6.0(2)A4(2)', '6.0(2)A4(3)',
        '6.0(2)A4(4)', '6.0(2)A4(5)', '6.0(2)A4(6)', '6.0(2)A6(1)', '6.0(2)A6(1a)', '6.0(2)A6(2)',
        '6.0(2)A6(2a)', '6.0(2)A6(3)', '6.0(2)A6(3a)', '6.0(2)A6(4)', '6.0(2)A6(4a)', '6.0(2)A6(5)',
        '6.0(2)A6(5a)', '6.0(2)A6(5b)', '6.0(2)A6(6)', '6.0(2)A6(7)', '6.0(2)A6(8)', '6.0(2)A7(1)',
        '6.0(2)A7(1a)', '6.0(2)A7(2)', '6.0(2)A7(2a)', '6.0(2)A8(1)', '6.0(2)A8(2)', '6.0(2)A8(3)',
        '6.0(2)A8(4)', '6.0(2)A8(4a)', '6.0(2)A8(5)', '6.0(2)A8(6)', '6.0(2)A8(7)', '6.0(2)A8(7a)',
        '6.0(2)A8(7b)', '6.0(2)A8(8)', '6.0(2)A8(9)', '6.0(2)A8(10)', '6.0(2)A8(10a)', '6.0(2)A8(11)',
        '6.0(2)A8(11a)', '6.0(2)A8(11b)',

        # 6.0(2)U versions
        '6.0(2)U2(1)', '6.0(2)U2(2)', '6.0(2)U2(3)', '6.0(2)U2(4)', '6.0(2)U2(5)', '6.0(2)U2(6)',
        '6.0(2)U3(1)', '6.0(2)U3(2)', '6.0(2)U3(3)', '6.0(2)U3(4)', '6.0(2)U3(5)', '6.0(2)U3(6)',
        '6.0(2)U3(7)', '6.0(2)U3(8)', '6.0(2)U3(9)', '6.0(2)U4(1)', '6.0(2)U4(2)', '6.0(2)U4(3)',
        '6.0(2)U4(4)', '6.0(2)U5(1)', '6.0(2)U5(2)', '6.0(2)U5(3)', '6.0(2)U5(4)', '6.0(2)U6(1)',
        '6.0(2)U6(2)', '6.0(2)U6(3)', '6.0(2)U6(4)', '6.0(2)U6(5)', '6.0(2)U6(6)', '6.0(2)U6(7)',
        '6.0(2)U6(8)', '6.0(2)U6(9)', '6.0(2)U6(10)', '6.0(2)U6(1a)', '6.0(2)U6(2a)', '6.0(2)U6(3a)',
        '6.0(2)U6(4a)', '6.0(2)U6(5a)', '6.0(2)U6(5b)', '6.0(2)U6(5c)',

        # 6.2 versions
        '6.2(1)', '6.2(2)', '6.2(2a)', '6.2(3)', '6.2(5)', '6.2(5a)', '6.2(5b)', '6.2(6)', '6.2(6a)',
        '6.2(6b)', '6.2(7)', '6.2(8)', '6.2(8a)', '6.2(8b)', '6.2(9)', '6.2(9a)', '6.2(9b)', '6.2(9c)',
        '6.2(10)', '6.2(11)', '6.2(11b)', '6.2(11c)', '6.2(11d)', '6.2(11e)', '6.2(12)', '6.2(13)',
        '6.2(13a)', '6.2(13b)', '6.2(14)', '6.2(15)', '6.2(16)', '6.2(17)', '6.2(18)', '6.2(19)',
        '6.2(20)', '6.2(20a)', '6.2(21)', '6.2(22)', '6.2(23)', '6.2(24)', '6.2(24a)', '6.2(25)',
        '6.2(27)', '6.2(29)', '6.2(31)', '6.2(33)',

        # 7.0(3) versions
        '7.0(3)F1(1)', '7.0(3)F2(1)', '7.0(3)F2(2)', '7.0(3)F3(1)', '7.0(3)F3(2)', '7.0(3)F3(3)',
        '7.0(3)F3(3a)', '7.0(3)F3(3c)', '7.0(3)F3(4)', '7.0(3)F3(5)', '7.0(3)I2(1)', '7.0(3)I2(1a)',
        '7.0(3)I2(2)', '7.0(3)I2(2a)', '7.0(3)I2(2b)', '7.0(3)I2(2c)', '7.0(3)I2(2d)', '7.0(3)I2(2e)',
        '7.0(3)I2(3)', '7.0(3)I2(4)', '7.0(3)I2(5)', '7.0(3)I3(1)', '7.0(3)I4(1)', '7.0(3)I4(2)',
        '7.0(3)I4(3)', '7.0(3)I4(4)', '7.0(3)I4(5)', '7.0(3)I4(6)', '7.0(3)I4(7)', '7.0(3)I4(8)',
        '7.0(3)I4(8a)', '7.0(3)I4(8b)', '7.0(3)I4(8z)', '7.0(3)I4(9)', '7.0(3)I5(1)', '7.0(3)I5(2)',
        '7.0(3)I6(1)', '7.0(3)I6(2)', '7.0(3)I7(1)', '7.0(3)I7(2)', '7.0(3)I7(3)', '7.0(3)I7(4)',
        '7.0(3)I7(5)', '7.0(3)I7(5a)', '7.0(3)I7(6)', '7.0(3)I7(7)', '7.0(3)I7(8)', '7.0(3)I7(9)',
        '7.0(3)I7(10)',

        # 7.1-7.3 versions
        '7.1(0)N1(1)', '7.1(0)N1(1a)', '7.1(0)N1(1b)', '7.1(1)N1(1)', '7.1(2)N1(1)', '7.1(3)N1(1)',
        '7.1(3)N1(2)', '7.1(4)N1(1)', '7.1(5)N1(1)', '7.1(5)N1(1b)', '7.2(0)D1(1)', '7.2(1)D1(1)',
        '7.2(2)D1(1)', '7.2(2)D1(2)', '7.3(0)D1(1)', '7.3(0)DX(1)', '7.3(0)DY(1)', '7.3(0)N1(1)',
        '7.3(1)D1(1)', '7.3(1)DY(1)', '7.3(1)N1(1)', '7.3(2)D1(1)', '7.3(2)D1(2)', '7.3(2)D1(3)',
        '7.3(2)D1(3a)', '7.3(2)N1(1)', '7.3(3)N1(1)', '7.3(3)D1(1)', '7.3(4)D1(1)', '7.3(4)N1(1)',
        '7.3(5)D1(1)', '7.3(5)N1(1)', '7.3(6)D1(1)', '7.3(6)N1(1)', '7.3(7)D1(1)', '7.3(7)N1(1)',
        '7.3(7)N1(1a)', '7.3(7)N1(1b)', '7.3(8)D1(1)', '7.3(8)N1(1)', '7.3(9)D1(1)', '7.3(9)N1(1)',
        '7.3(10)N1(1)', '7.3(11)N1(1)', '7.3(12)N1(1)', '7.3(13)N1(1)',

        # 8.x versions
        '8.0(1)', '8.1(1)', '8.1(1a)', '8.1(1b)', '8.1(2)', '8.1(2a)', '8.2(1)', '8.2(2)', '8.2(3)',
        '8.2(4)', '8.2(5)', '8.2(6)', '8.2(7)', '8.2(7a)', '8.2(8)', '8.2(9)', '8.2(10)', '8.3(1)',
        '8.3(2)', '8.4(1)', '8.4(1a)', '8.4(2)', '8.4(2a)', '8.4(2b)', '8.4(2c)', '8.4(2d)', '8.4(2e)',
        '8.4(2f)', '8.4(3)', '8.4(4)', '8.4(4a)', '8.4(5)', '8.4(6)', '8.4(6a)', '8.4(7)', '8.5(1)',

        # 9.x versions
        '9.2(1)', '9.2(1a)', '9.2(2)', '9.2(2t)', '9.2(2v)', '9.2(3)', '9.2(4)', '9.3(1)', '9.3(2)',
        '9.3(2a)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(7)', '9.3(7a)', '9.3(8)', '9.3(9)',
        '9.3(10)', '9.3(11)',

        # 10.x versions
        '10.1(1)', '10.1(2)', '10.1(2t)', '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(3)', '10.2(3t)',
        '10.2(3v)', '10.2(4)', '10.2(5)', '10.3(1)', '10.3(2)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if LLDP is enabled on the device
    lldp_enabled = 'enabled' in commands.show_feature

    if lldp_enabled:
        # Check if LLDP receive is enabled on any interface
        lldp_rx_enabled = 'Enable (tx/rx/dcbx): Y/Y/' in commands.show_lldp_interface
        
        assert not lldp_rx_enabled, (
            f"Device {device.name} is vulnerable to CVE-2024-20294. "
            "The device is running a vulnerable version AND has LLDP receive enabled. "
            "Consider disabling LLDP receive on all interfaces or upgrading to a fixed software version. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-lldp-dos-z7PncTgt"
        )
