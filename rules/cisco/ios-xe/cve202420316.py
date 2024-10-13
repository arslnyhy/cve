from comfy import medium

@medium(
    name='rule_cve202420316',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(
        show_netconf='show running-config | include netconf-yang',
        show_restconf='show running-config | include restconf',
        show_logs='show logging | include DMI'
    ),
)
def rule_cve202420316(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco IOS XE Software
    where an unauthenticated, remote attacker could bypass IPv4 ACLs using NETCONF
    or RESTCONF protocols.

    The vulnerability is due to improper handling of error conditions when an
    authorized device administrator updates an IPv4 ACL using these protocols.
    """

    # Check if NETCONF is enabled
    netconf_enabled = 'netconf-yang' in commands.show_netconf
    # Check if RESTCONF is enabled
    restconf_enabled = 'restconf' in commands.show_restconf

    # If either NETCONF or RESTCONF is enabled, the device might be vulnerable
    if netconf_enabled or restconf_enabled:
        # Check device logs for indicators of compromise
        logs = commands.show_logs
        sync_needed = '%DMI-5-SYNC_NEEDED' in logs
        sync_start = '%DMI-5-SYNC_START' in logs
        sync_err = '%DMI-3-SYNC_ERR' in logs
        dmi_degraded = '%DMI-3-DMI_DEGRADED' in logs

        # If any of these log messages are present, the device is in a vulnerable state
        assert not (sync_needed or sync_start or sync_err or dmi_degraded), (
            "Device logs indicate potential vulnerability due to NETCONF/RESTCONF ACL bypass."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dmi-acl-bypass-Xv8FO8Vz"
        )
    else:
        # If neither NETCONF nor RESTCONF is enabled, the device is not vulnerable
        assert True, "NETCONF and RESTCONF are disabled, device is not vulnerable."
