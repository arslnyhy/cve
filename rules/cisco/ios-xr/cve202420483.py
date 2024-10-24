from comfy import high

@high(
    name='rule_cve202420483',
    platform=['cisco_iosxr'],
    commands=dict(show_pon_ctlr='show running-config pon-ctlr'),
)
def rule_cve202420483(configuration, commands, device, devices):
    """
    This rule checks for the presence of the PON Controller configuration
    in Cisco IOS XR devices. If the PON Controller is enabled, the device
    may be vulnerable to CVE-2024-20483, which allows for command injection
    attacks due to insufficient validation of arguments in configuration commands.
    """

    # Extract the output of the 'show running-config pon-ctlr' command
    pon_ctlr_output = commands.show_pon_ctlr

    # Check if the PON Controller is configured
    if 'pon-ctlr' in pon_ctlr_output:
        # If 'pon-ctlr' is found in the configuration, raise an assertion
        # indicating potential vulnerability to CVE-2024-20483
        assert False, (
            f"Device {device.name} is potentially vulnerable to CVE-2024-20483. "
            "The PON Controller is enabled, which could allow command injection attacks."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ponctlr-ci-OHcHmsFL"
        )
    else:
        # If 'pon-ctlr' is not found, the device is not affected by this vulnerability
        assert True
