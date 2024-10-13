from comfy import high


@high(
    name='rule_cve202420276',
    platform=['cisco_ios'],
    commands=dict(
        show_running_config='show running-config | include interface|port-security|device classifier|system-auth-control|port-control|mab'
    ),
)
def rule_cve202420276(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2024-20276 vulnerability in Cisco Catalyst 6000 Series Switches.
    The vulnerability is due to improper handling of process-switched traffic, which can be exploited by an
    unauthenticated, adjacent attacker to cause a denial of service (DoS) condition by reloading the device.
    """
    # Extract the output of the show running-config command
    config_output = commands.show_running_config

    # Check if port security is enabled
    port_security_enabled = 'switchport port-security' in config_output

    # Check if device classifier is enabled
    device_classifier_enabled = 'device classifier' in config_output

    # Check if AAA is enabled
    aaa_enabled = any(keyword in config_output for keyword in [
        'dot1x system-auth-control',
        'authentication order',
        'authentication priority',
        'authentication port-control',
        'mab'
    ])

    # If any of the above features are enabled, the device is vulnerable
    is_vulnerable = port_security_enabled or device_classifier_enabled or aaa_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20276. "
        "Port security, device classifier, or AAA is enabled, which makes the device susceptible to DoS attacks. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-dos-Hq4d3tZG"
    )
