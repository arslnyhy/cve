from comfy import high

@high(
    name='rule_cve202420483',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_pon_ctlr='show running-config pon-ctlr'
    ),
)
def rule_cve202420483(configuration, commands, device, devices):
    """
    This rule checks for the presence of the PON Controller configuration
    in Cisco IOS XR devices. If the PON Controller is enabled, the device
    may be vulnerable to CVE-2024-20483, which allows for command injection
    attacks due to insufficient validation of arguments in configuration commands.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 24.x versions
        '24.1.1',
        '24.1.2',
        '24.2.1',
        '24.2.11',
        '24.3.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the 'show running-config pon-ctlr' command
    pon_ctlr_output = commands.show_pon_ctlr

    # Check if the PON Controller is configured
    pon_ctlr_enabled = 'pon-ctlr' in pon_ctlr_output

    # Assert that the PON Controller is not enabled if the version is vulnerable
    assert not pon_ctlr_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-20483. "
        "The device is running a vulnerable version AND has the PON Controller enabled, "
        "which could allow command injection attacks. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ponctlr-ci-OHcHmsFL"
    )
