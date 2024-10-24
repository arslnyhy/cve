from comfy import medium

@medium(
    name='rule_cve202420315',
    platform=['cisco_xr'],
    commands=dict(
        show_running_config='show running-config'
    ),
)
def rule_cve202420315(configuration, commands, device, devices):
    """
    This rule checks for the presence of ingress ACLs in the running configuration,
    which could be exploited due to the CVE-2024-20315 vulnerability.
    """

    # Extract the output of the 'show running-config' command
    running_config_output = commands.show_running_config

    # Check if there is an ingress ACL applied anywhere in the running configuration
    if 'access-group' in running_config_output and 'ingress' in running_config_output:
        # If an ingress ACL is found, the device is vulnerable
        assert False, "Ingress ACL found in running configuration, which is vulnerable to CVE-2024-20315."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-acl-bypass-RZU5NL3e"

    # If no ingress ACLs are found, the device is not vulnerable
    assert True, "No ingress ACLs found in running configuration, device is not vulnerable to CVE-2024-20315."
