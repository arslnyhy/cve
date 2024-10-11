@medium(
    name='rule_cve202420291',
    platform=['cisco_nxos'],
    commands=dict(
        show_port_channel='show running-config interface port-channel',
        show_acl_entries='show system internal access-list interface port-channel input entries detail'
    ),
)
def rule_cve202420291(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20291 vulnerability in Cisco Nexus 3000 and 9000 Series Switches.
    The vulnerability allows traffic to pass through port channel subinterfaces with misconfigured ACLs.
    """

    # Check if the device is running a vulnerable NX-OS version
    vulnerable_versions = ['9.3(10)', '9.3(11)', '9.3(12)']
    if any(version in configuration for version in vulnerable_versions):
        # Check for ingress ACL configuration on port channel subinterfaces
        if 'ip access-group' in commands.show_port_channel:
            # Extract port channel interfaces with ACLs
            port_channels_with_acls = []
            for line in commands.show_port_channel.splitlines():
                if 'interface port-channel' in line:
                    current_interface = line.split()[-1]
                if 'ip access-group' in line:
                    port_channels_with_acls.append(current_interface)

            # Verify ACL programming for each port channel subinterface
            for port_channel in port_channels_with_acls:
                acl_entries = commands.show_acl_entries
                if port_channel not in acl_entries:
                    # If no ACL entries are found for a configured port channel, the vulnerability is present
                    assert False, f"Vulnerability CVE-2024-20291 detected on {device.name}: Port channel {port_channel} has misconfigured ACL."
                    "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-po-acl-TkyePgvL"

    # If no issues are found, the test passes
    assert True
