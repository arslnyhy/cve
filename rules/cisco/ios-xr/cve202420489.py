from comfy import high

@high(
    name='rule_cve202420489',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_pon_ctlr='show running-config pon-ctlr'
    ),
)
def rule_cve202420489(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20489 vulnerability in Cisco IOS XR devices.
    The vulnerability involves the storage of unencrypted MongoDB credentials in the PON Controller configuration file.
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

    # Retrieve the output of the 'show running-config pon-ctlr' command and check for cleartext passwords
    has_cleartext_password = '"password"' in commands.show_pon_ctlr

    # Assert that no cleartext passwords are found in the configuration
    assert not has_cleartext_password, (
        f"Device {device.name} is vulnerable to CVE-2024-20489. "
        "The device is running a vulnerable version AND has MongoDB passwords stored in cleartext in the PON Controller configuration. "
        "Ensure the configuration uses 'password_opts' for secure storage. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ponctlr-ci-OHcHmsFL"
    )
