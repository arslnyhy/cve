from comfy import high

@high(
    name='rule_cve202436505',
    platform=['fortinet'],
    commands=dict(
        show_version='get system status'
    ),
)
def rule_cve202436505(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-36505 vulnerability in Fortinet FortiOS.
    The vulnerability is an improper access control issue that may allow an attacker
    who has already obtained write access to the underlying system to bypass the file
    integrity checking system.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for FortiOS
    vulnerable_fortios_versions = [
        '7.4.0', '7.4.1', '7.4.2', '7.4.3',
        '7.2.5', '7.2.6', '7.2.7',
        '7.0.12', '7.0.13', '7.0.14',
        '6.4.13', '6.4.14', '6.4.15'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_fortios_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-36505. "
        "The device is running a vulnerable version, which makes it susceptible to improper access control issues. "
        "For more information, see https://fortiguard.fortinet.com/psirt/FG-IR-24-012"
    )
