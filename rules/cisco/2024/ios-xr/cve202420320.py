from comfy import high

@high(
    name='rule_cve202420320',
    platform=['cisco_xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202420320(configuration, commands, device, devices):
    """
    This rule checks for the presence of a vulnerability in Cisco IOS XR Software
    that could allow privilege escalation via the SSH client feature. The vulnerability
    affects specific versions of the software running on certain Cisco routers.
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Define the vulnerable software versions from the notepad
    vulnerable_versions = [
        # 7.2.x versions
        '7.2.1', '7.2.2',
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
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1'
    ]

    # Check if the device's software version is listed as vulnerable
    is_vulnerable = any(version in show_version_output for version in vulnerable_versions)

    # Assert that the device is not running a vulnerable version
    # If the device is running a vulnerable version, the test will fail
    assert not is_vulnerable, (
        f"Device {device.name} is running a vulnerable version of Cisco IOS XR Software. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20320. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ssh-privesc-eWDMKew3"
    )
