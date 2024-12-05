from comfy import high

@high(
    name='rule_cve202420313',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ospf|distribute link-state'
    ),
)
def rule_cve202420313(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific configuration that makes Cisco IOS XE devices
    vulnerable to CVE-2024-20313. The vulnerability is due to improper validation of OSPF updates,
    which can be exploited to cause a denial of service.

    The test checks if the device is running a vulnerable version and if the 'router ospf <PID>' 
    and 'distribute link-state' configurations are present in the device's running configuration. 
    If both conditions are met, the device is considered vulnerable.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 17.5.x versions
        '17.5.1', '17.5.1a',
        # 17.6.x versions
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.5a',
        # 17.7.x versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        # 17.8.x versions
        '17.8.1', '17.8.1a',
        # 17.9.x versions
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a', '17.9.1y1',
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Retrieve the output of the command that checks for OSPF and distribute link-state configurations
    ospf_config = commands.show_running_config

    # Check if both 'router ospf' and 'distribute link-state' are present in the configuration
    is_vulnerable = 'router ospf' in ospf_config and 'distribute link-state' in ospf_config

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the assertion will fail, indicating a high severity issue
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20313. "
        "The device is running a vulnerable version AND has OSPF with distribute link-state enabled. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ospf-dos-dR9Sfrxp"
    )
