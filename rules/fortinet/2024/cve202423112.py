from comfy import high

@high(
    name='rule_cve202423112',
    platform=['fortinet'],
    commands=dict(
        show_version='get system status'
    ),
)
def rule_cve202423112(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-23112 vulnerability in Fortinet FortiOS.
    The vulnerability is an authorization bypass through user-controlled key, which may allow
    an authenticated attacker to gain access to another user’s bookmark via URL manipulation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for FortiOS
    vulnerable_fortios_versions = [
        '7.4.0', '7.4.1',
        '7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5', '7.2.6',
        '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8', '7.0.9', '7.0.10', '7.0.11', '7.0.12', '7.0.13',
        '6.4.7', '6.4.8', '6.4.9', '6.4.10', '6.4.11', '6.4.12', '6.4.13', '6.4.14'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_fortios_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-23112. "
        "The device is running a vulnerable version, which makes it susceptible to authorization bypass attacks. "
        "For more information, see https://fortiguard.com/psirt/FG-IR-24-013"
    )
