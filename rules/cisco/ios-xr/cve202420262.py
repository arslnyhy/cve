@medium(
    name='rule_cve202420262',
    platform=['cisco_xr'],
    commands=dict(
        show_run='show running-config',
        show_features='show features'
    ),
)
def rule_cve202420262(configuration, commands, device, devices):
    """
    This rule checks for the presence of SCP and SFTP features on Cisco IOS XR devices.
    The vulnerability CVE-2024-20262 allows an authenticated local attacker to create or overwrite
    files in a system directory, leading to a denial of service (DoS) condition. This is due to
    improper validation of SCP and SFTP CLI input parameters.

    The rule checks if SCP and SFTP are enabled, as these features are necessary for the vulnerability
    to be exploited. If they are enabled, it raises a warning.
    """

    # Check if SCP is enabled in the device configuration
    scp_enabled = 'scp' in commands.show_features.lower()
    # Check if SFTP is enabled in the device configuration
    sftp_enabled = 'sftp' in commands.show_features.lower()

    # Assert that neither SCP nor SFTP is enabled to pass the test
    assert not (scp_enabled or sftp_enabled), (
        "SCP or SFTP is enabled on the device, which could make it vulnerable to CVE-2024-20262. "
        "Consider disabling these features or applying the recommended software updates."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-dos-kb6sUUHw"
    )
