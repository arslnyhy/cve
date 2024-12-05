from comfy import high

@high(
    name='rule_cve202447490',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware'
    ),
)
def rule_cve202447490(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47490 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS condition
    by sending specific MPLS packets that are incorrectly forwarded to the RE.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.3R3', '22.3R3-S1', '22.3R3-S2',
        '22.4R3', '22.4R3-S1',
        '23.2R1',
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is ACX 7000 Series
    chassis_output = commands.show_chassis_hardware
    is_acx7k_platform = 'ACX7' in chassis_output

    # Assert that the device is not vulnerable
    assert not is_acx7k_platform, (
        f"Device {device.name} is vulnerable to CVE-2024-47490. "
        "The device is running a vulnerable version of Junos OS Evolved on ACX 7000 Series hardware, "
        "which makes it susceptible to DoS attacks through improper MPLS packet handling. "
        "For more information, see https://supportportal.juniper.net/JSA83009"
    )
