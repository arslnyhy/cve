from comfy import medium

@medium(
    name='rule_cve202420262',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_run='show running-config'
    ),
)
def rule_cve202420262(configuration, commands, device, devices):
    """
    This rule checks for the presence of SCP and SFTP features on Cisco IOS XR devices.
    The vulnerability CVE-2024-20262 allows an authenticated local attacker to create or overwrite
    files in a system directory, leading to a denial of service (DoS) condition. This is due to
    improper validation of SCP and SFTP CLI input parameters.

    The rule checks if the device is running a vulnerable version and if SCP and SFTP are enabled,
    as these features are necessary for the vulnerability to be exploited.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 5.2.x versions
        '5.2.0', '5.2.1', '5.2.2', '5.2.3', '5.2.4', '5.2.5', '5.2.47',
        # 5.3.x versions
        '5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4',
        # 6.0.x versions
        '6.0.0', '6.0.1', '6.0.2',
        # 6.1.x versions
        '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.12', '6.1.22', '6.1.32', '6.1.36', '6.1.42',
        # 6.2.x versions
        '6.2.1', '6.2.2', '6.2.3', '6.2.11', '6.2.25',
        # 6.3.x versions
        '6.3.2', '6.3.3', '6.3.15',
        # 6.4.x versions
        '6.4.1', '6.4.2', '6.4.3',
        # 6.5.x versions
        '6.5.1', '6.5.2', '6.5.3', '6.5.25', '6.5.26', '6.5.28', '6.5.29', '6.5.32', '6.5.33',
        # 6.6.x versions
        '6.6.2', '6.6.3', '6.6.4', '6.6.25',
        # 6.7.x versions
        '6.7.2', '6.7.4',
        # 7.0.x versions
        '7.0.1', '7.0.2', '7.0.12', '7.0.14',
        # 7.1.x versions
        '7.1.1', '7.1.2',
        # 7.2.x versions
        '7.2.0', '7.2.1', '7.2.2',
        # 7.3.x versions
        '7.3.1', '7.3.2', '7.3.3', '7.3.5', '7.3.15',
        # 7.4.x versions
        '7.4.1', '7.4.2',
        # 7.5.x versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5',
        # 7.6.x versions
        '7.6.1', '7.6.2',
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2',
        # 7.9.x versions
        '7.9.1', '7.9.2',
        # 7.10.x versions
        '7.10.1', '7.10.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if SCP is enabled in the device configuration
    scp_enabled = 'scp' in commands.show_run
    # Check if SFTP is enabled in the device configuration
    sftp_enabled = 'sftp' in commands.show_run

    # Assert that neither SCP nor SFTP is enabled to pass the test
    assert not (scp_enabled or sftp_enabled), (
        f"Device {device.name} is vulnerable to CVE-2024-20262. "
        "The device is running a vulnerable version AND has SCP or SFTP enabled. "
        "Consider disabling these features or applying the recommended software updates. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-dos-kb6sUUHw"
    )
