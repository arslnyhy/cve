@medium(
    name='rule_cve202420315',
    platform=['cisco_xr'],
    commands=dict(
        show_mpls_interfaces='show mpls interfaces',
        show_running_config='show running-config'
    ),
)
def rule_cve202420315(configuration, commands, device, devices):
    """
    This rule checks for the presence of ingress ACLs on MPLS interfaces,
    which could be exploited due to the CVE-2024-20315 vulnerability.
    """

    # Extract the output of the 'show mpls interfaces' command
    mpls_interfaces_output = commands.show_mpls_interfaces

    # Find all MPLS interfaces that are enabled
    enabled_mpls_interfaces = []
    for line in mpls_interfaces_output.splitlines():
        if 'Yes' in line:  # Check if the interface is enabled
            interface = line.split()[0]  # Extract the interface name
            enabled_mpls_interfaces.append(interface)

    # Check each enabled MPLS interface for ingress ACLs
    for interface in enabled_mpls_interfaces:
        # Construct the command to check the running configuration of the interface
        show_interface_command = f'show running-config interface {interface}'
        interface_config_output = device.cli(show_interface_command)

        # Check if there is an ingress ACL applied on the interface
        if 'access-group' in interface_config_output and 'ingress' in interface_config_output:
            # If an ingress ACL is found, the device is vulnerable
            assert False, f"Ingress ACL found on MPLS interface {interface}, which is vulnerable to CVE-2024-20315."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-acl-dos-4Xj4555G"

    # If no ingress ACLs are found on any MPLS interfaces, the device is not vulnerable
    assert True, "No ingress ACLs found on MPLS interfaces, device is not vulnerable to CVE-2024-20315."
