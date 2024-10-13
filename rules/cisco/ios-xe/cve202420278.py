from comfy import medium

@medium(
    name='rule_cve202420278',
    platform=['cisco_xe'],
    commands=dict(show_netconf='show running-config | include netconf-yang'),
)
def rule_cve202420278(configuration, commands, device, devices):
    """
    This rule checks for the presence of the NETCONF feature on Cisco IOS XE devices.
    If NETCONF is enabled, the device may be vulnerable to privilege escalation
    due to CVE-2024-20278. The vulnerability allows an authenticated, remote attacker
    to elevate privileges to root by sending crafted input over NETCONF.
    """

    # Retrieve the output of the command that checks for NETCONF configuration
    netconf_output = commands.show_netconf

    # Check if NETCONF is enabled by looking for 'netconf-yang' in the command output
    netconf_enabled = 'netconf-yang' in netconf_output

    # Assert that NETCONF is not enabled to pass the test, indicating the device is not vulnerable
    # If NETCONF is enabled, the test will fail, indicating potential vulnerability
    assert not netconf_enabled, (
        f"Device {device.name} with IP {device.ip_address} has NETCONF enabled, "
        "which may expose it to CVE-2024-20278 privilege escalation vulnerability. "
        "Consider updating the software to a fixed version."
        "For more information, see hhttps://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-seAx6NLX"
    )
