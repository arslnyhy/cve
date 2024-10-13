@high(
    name='rule_cve202420489',
    platform=['cisco_iosxr'],
    commands=dict(show_pon_ctlr='show running-config pon-ctlr'),
)
def rule_cve202420489(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20489 vulnerability in Cisco IOS XR devices.
    The vulnerability involves the storage of unencrypted MongoDB credentials in the PON Controller configuration file.
    """

    # Retrieve the output of the 'show running-config pon-ctlr' command
    pon_ctlr_config = commands.show_pon_ctlr

    # Check if the configuration contains the MongoDB password in cleartext
    # We are looking for the presence of "password" field in the configuration
    # This indicates that the password is stored in cleartext, which is a vulnerability
    assert '"password":' not in pon_ctlr_config, (
        f"Device {device.name} is vulnerable to CVE-2024-20489. "
        "The MongoDB password is stored in cleartext in the PON Controller configuration."
    )

    # If the password is stored using the 'password_opts' field, it indicates a secure configuration
    # This means the password is stored using a keyring, which mitigates the vulnerability
    assert '"password_opts":' in pon_ctlr_config, (
        f"Device {device.name} is not using secure password storage for MongoDB credentials. "
        "Ensure the configuration uses 'password_opts' for secure storage."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ponctlr-ci-OHcHmsFL"
    )
