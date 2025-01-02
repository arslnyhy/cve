from comfy import high

@high(
    name='rule_cve202423111',
    platform=['fortinet'],
    commands=dict(
        show_version='get system status'
    ),
)
def rule_cve202423111(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-23111 vulnerability in Fortinet FortiOS and FortiProxy.
    The vulnerability is an improper neutralization of input during web page generation ('Cross-site Scripting').
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions for FortiOS
    vulnerable_fortios_versions = [
        '7.4.0', '7.4.1', '7.4.2',
        '7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5', '7.2.6',
        '7.0.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8', '7.0.9', '7.0.10', '7.0.11', '7.0.12', '7.0.13'
    ]

    # List of vulnerable software versions for FortiProxy
    vulnerable_fortiproxy_versions = [
        '7.4.0', '7.4.1', '7.4.2',
        '7.2.0', '7.2.1', '7.2.2', '7.2.3', '7.2.4', '7.2.5', '7.2.6', '7.2.7', '7.2.8',
        '7.0.0', '7.0.1', '7.0.2', '7.0.3', '7.0.4', '7.0.5', '7.0.6', '7.0.7', '7.0.8', '7.0.9', '7.0.10', '7.0.11', '7.0.12', '7.0.13', '7.0.14'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_fortios_versions + vulnerable_fortiproxy_versions)

    # Assert that the device is not vulnerable
    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-23111. "
        "The device is running a vulnerable version, which makes it susceptible to cross-site scripting attacks. "
        "For more information, see https://fortiguard.fortinet.com/psirt/FG-IR-23-471"
    )
