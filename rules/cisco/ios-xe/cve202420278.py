from comfy import medium

@medium(
    name='rule_cve202420278',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_netconf='show running-config | include netconf-yang'
    ),
)
def rule_cve202420278(configuration, commands, device, devices):
    """
    This rule checks for the presence of the NETCONF feature on Cisco IOS XE devices.
    If NETCONF is enabled, the device may be vulnerable to privilege escalation
    due to CVE-2024-20278. The vulnerability allows an authenticated, remote attacker
    to elevate privileges to root by sending crafted input over NETCONF.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.6.x versions
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.6', '17.6.6a',
        '17.6.5a',
        # 17.7.x versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        # 17.8.x versions
        '17.8.1', '17.8.1a',
        # 17.9.x versions
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.4', '17.9.1y1', '17.9.4a',
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW',
        # 17.12.x versions
        '17.12.1', '17.12.1w', '17.12.1a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Retrieve the output of the command that checks for NETCONF configuration
    netconf_output = commands.show_netconf

    # Check if NETCONF is enabled by looking for 'netconf-yang' in the command output
    netconf_enabled = 'netconf-yang' in netconf_output

    # Assert that NETCONF is not enabled to pass the test, indicating the device is not vulnerable
    # If NETCONF is enabled, the test will fail, indicating potential vulnerability
    assert not netconf_enabled, (
        f"Device {device.name} with IP {device.ip_address} is vulnerable to CVE-2024-20278. "
        "The device is running a vulnerable version AND has NETCONF enabled, "
        "which may expose it to privilege escalation vulnerability. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-seAx6NLX"
    )
