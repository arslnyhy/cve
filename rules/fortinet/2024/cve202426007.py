from comfy import high

@high(
    name='rule_cve202426007',
    platform=['fortinet'],
    commands=dict(
        show_version='get system status'
    ),
)
def rule_cve202426007(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-26007 vulnerability in Fortinet FortiOS.
    The vulnerability is an improper check or handling of exceptional conditions,
    which allows an unauthenticated attacker to provoke a denial of service on the
    administrative interface via crafted HTTP requests.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for FortiOS
    vulnerable_fortios_versions = [
        '7.4.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_fortios_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-26007. "
        "The device is running a vulnerable version, which makes it susceptible to denial of service attacks. "
        "For more information, see https://fortiguard.com/psirt/FG-IR-24-017"
    )
