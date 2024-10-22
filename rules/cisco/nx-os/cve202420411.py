from comfy import medium

@medium(
    name='rule_cve202420411',
    platform=['cisco_nxos'],
    commands=dict(
        show_feature='show feature | include bash',
        show_running_config='show running-config | include shelltype'
    ),
)
def rule_cve202420411(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20411 vulnerability in Cisco NX-OS Software.
    The vulnerability allows an authenticated, local attacker with privileges to access
    the Bash shell to execute arbitrary code as root on an affected device.
    
    The test verifies if the Bash shell is enabled or if any users are configured
    to use the Bash shell at login, which are prerequisites for exploiting this vulnerability.
    """

    # Check if the Bash shell feature is enabled
    bash_feature_output = commands.show_feature
    is_bash_enabled = 'enabled' in bash_feature_output

    # Check if any users are configured to use the Bash shell at login
    bash_shelltype_output = commands.show_running_config
    is_bash_shelltype_configured = 'shelltype bash' in bash_shelltype_output

    # Assert that neither the Bash shell is enabled nor any users are configured to use it
    # If either condition is true, the device is vulnerable to CVE-2024-20411
    assert not (is_bash_enabled or is_bash_shelltype_configured), (
        f"Device {device.name} is vulnerable to CVE-2024-20411: "
        "Bash shell is enabled or users are configured to use Bash shell at login."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bshacepe-bApeHSx7"
    )
