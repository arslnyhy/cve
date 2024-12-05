from comfy import medium

@medium(
    name='rule_cve202420291',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_port_channel='show running-config interface port-channel',
        show_acl_entries='show system internal access-list interface port-channel input entries detail'
    ),
)
def rule_cve202420291(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20291 vulnerability in Cisco Nexus 3000 and 9000 Series Switches.
    The vulnerability allows traffic to pass through port channel subinterfaces with misconfigured ACLs.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 9.3.x versions
        '9.3(10)',
        '9.3(11)',
        '9.3(12)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

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
                assert False, (
                    f"Device {device.name} is vulnerable to CVE-2024-20291. "
                    f"The device is running a vulnerable version AND port channel {port_channel} has misconfigured ACL. "
                    "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-po-acl-TkyePgvL"
                )
