from comfy import medium

@medium(
    name='rule_cve202420294',
    platform=['cisco_nxos', 'cisco_fxos'],
    commands=dict(
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

    # Check if LLDP is enabled on the device
    lldp_enabled = 'enabled' in commands.show_feature

    if lldp_enabled:
        # Check if LLDP receive is enabled on any interface
        lldp_rx_enabled = 'Enable (tx/rx/dcbx): Y/Y/' in commands.show_lldp_interface
        
        assert not lldp_rx_enabled, (
            "LLDP receive is enabled on one or more interfaces, which is vulnerable to CVE-2024-20294. "
            "Consider disabling LLDP receive on all interfaces or upgrading to a fixed software version. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-lldp-dos-z7PncTgt"
        )
    else:
        print("LLDP is disabled globally. The device is not vulnerable to CVE-2024-20294.")
