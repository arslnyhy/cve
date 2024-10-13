from comfy import high

@high(
    name='rule_cve202420313',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(
        show_running_config='show running-config | include ospf|distribute link-state'
    ),
)
def rule_cve202420313(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific configuration that makes Cisco IOS XE devices
    vulnerable to CVE-2024-20313. The vulnerability is due to improper validation of OSPF updates,
    which can be exploited to cause a denial of service.

    The test checks if the 'router ospf <PID>' and 'distribute link-state' configurations are present
    in the device's running configuration. If both are found, the device is considered vulnerable.
    """

    # Retrieve the output of the command that checks for OSPF and distribute link-state configurations
    ospf_config = commands.show_running_config

    # Check if both 'router ospf' and 'distribute link-state' are present in the configuration
    is_vulnerable = 'router ospf' in ospf_config and 'distribute link-state' in ospf_config

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the assertion will fail, indicating a high severity issue
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20313. "
        "OSPF with distribute link-state is enabled."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ospf-dos-dR9Sfrxp"
    )
