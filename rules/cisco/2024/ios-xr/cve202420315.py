from comfy import medium

@medium(
    name='rule_cve202420315',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202420315(configuration, commands, device, devices):
    """
    This rule checks for the presence of ingress ACLs in the running configuration,
    which could be exploited due to the CVE-2024-20315 vulnerability. The test verifies
    if the device is running a vulnerable version and has ingress ACLs configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2',
        # 7.9.x versions
        '7.9.1', '7.9.2',
        # 7.10.x versions
        '7.10.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the 'show running-config' command
    running_config_output = commands.show_running_config

    # Check if there is an ingress ACL applied anywhere in the running configuration
    has_ingress_acl = 'access-group' in running_config_output and 'ingress' in running_config_output

    # Assert that no ingress ACLs are configured if the version is vulnerable
    assert not has_ingress_acl, (
        f"Device {device.name} is vulnerable to CVE-2024-20315. "
        "The device is running a vulnerable version AND has ingress ACLs configured. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-acl-bypass-RZU5NL3e"
    )
