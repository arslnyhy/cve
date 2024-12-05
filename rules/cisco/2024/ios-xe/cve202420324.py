from comfy import medium

@medium(
    name='rule_cve202420324',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_tech_wireless='show tech wireless',
        show_run='show running-config'
    ),
)
def rule_cve202420324(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco IOS XE Software
    that allows low-privileged users to access WLAN configuration details.

    The vulnerability is due to improper privilege checks, allowing the use of
    'show' and 'show tech wireless' commands to access sensitive configuration details.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 16.10.x versions
        '16.10.1', '16.10.1s', '16.10.1e',
        # 16.11.x versions
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2',
        # 16.12.x versions
        '16.12.1', '16.12.1s', '16.12.3', '16.12.8', '16.12.2s', '16.12.1t', '16.12.4',
        '16.12.3s', '16.12.4a', '16.12.5', '16.12.6', '16.12.6a', '16.12.7',
        # 17.1.x versions
        '17.1.1', '17.1.1s', '17.1.1t', '17.1.3',
        # 17.2.x versions
        '17.2.1', '17.2.1a',
        # 17.3.x versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.2a', '17.3.4', '17.3.5', '17.3.6', '17.3.4c',
        '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        # 17.4.x versions
        '17.4.1',
        # 17.5.x versions
        '17.5.1',
        # 17.6.x versions
        '17.6.1', '17.6.2', '17.6.3', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        # 17.7.x versions
        '17.7.1',
        # 17.8.x versions
        '17.8.1',
        # 17.9.x versions
        '17.9.1', '17.9.2', '17.9.3', '17.9.4', '17.9.4a',
        # 17.10.x versions
        '17.10.1', '17.10.1a',
        # 17.11.x versions
        '17.11.1',
        # 17.12.x versions
        '17.12.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the 'show tech wireless' command output contains sensitive information
    # that should not be accessible to low-privileged users.
    show_tech_output = commands.show_tech_wireless
    show_run_output = commands.show_run

    # Check for sensitive information in both outputs
    has_sensitive_info = ('password' in show_tech_output) or ('password' in show_run_output)

    # Assert that no sensitive information is exposed
    assert not has_sensitive_info, (
        f"Device {device.name} is vulnerable to CVE-2024-20324. "
        "The device is running a vulnerable version AND exposes WLAN configuration details through 'show tech wireless' or 'show running-config'. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-privesc-RjSMrmPK"
    )
