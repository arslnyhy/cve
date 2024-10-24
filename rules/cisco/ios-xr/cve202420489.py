from comfy import high

@high(
    name='rule_cve202420489',
    platform=['cisco_xr'],
    commands=dict(show_pon_ctlr='show running-config pon-ctlr'),
)
def rule_cve202420489(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20489 vulnerability in Cisco IOS XR devices.
    The vulnerability involves the storage of unencrypted MongoDB credentials in the PON Controller configuration file.
    """

    # Retrieve the output of the 'show running-config pon-ctlr' command
    is_vulnerable = '"password"' in commands.show_pon_ctlr
    

    assert not is_vulnerable, (
        f"The MongoDB password is stored in cleartext in the PON Controller configuration. "
        "Ensure the configuration uses 'password_opts' for secure storage."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ponctlr-ci-OHcHmsFL"
    )
