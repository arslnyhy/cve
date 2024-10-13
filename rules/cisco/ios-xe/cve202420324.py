from comfy import medium

@medium(
    name='rule_cve202420324',
    platform=['cisco_xe'],
    commands=dict(show_tech_wireless='show tech wireless', show_run='show running-config'),
)
def rule_cve202420324(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco IOS XE Software
    that allows low-privileged users to access WLAN configuration details.

    The vulnerability is due to improper privilege checks, allowing the use of
    'show' and 'show tech wireless' commands to access sensitive configuration details.
    """

    # Check if the 'show tech wireless' command output contains sensitive information
    # that should not be accessible to low-privileged users.
    show_tech_output = commands.show_tech_wireless
    assert 'password' not in show_tech_output, (
        "Vulnerability found: 'show tech wireless' exposes WLAN configuration details."
    )

    # Check if the running configuration contains any exposed passwords.
    # This checks for the presence of passwords in the configuration output.
    show_run_output = commands.show_run
    assert 'password' not in show_run_output, (
        "Vulnerability found: 'show running-config' exposes WLAN configuration details."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-privesc-RjSMrmPK"
    )
