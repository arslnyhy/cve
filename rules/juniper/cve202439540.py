from comfy import high

@high(
    name='rule_cve202439540',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_pfe_crashes='show system core-dumps | match pfe'
    )
)
def rule_cve202439540(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39540 vulnerability in Juniper Networks Junos OS on SRX Series
    and MX Series with SPC3. The vulnerability allows an unauthenticated, network-based attacker
    to cause a Denial of Service (DoS) by sending specific valid TCP traffic that causes PFE crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series or MX Series with SPC3
    chassis_output = commands.show_chassis_hardware
    if not ('SRX' in chassis_output or ('MX' in chassis_output and 'SPC3' in chassis_output)):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2R3-S5 is the only affected version
        '21.2R3-S5'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for recent PFE crashes
    crash_output = commands.show_pfe_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'pfe' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-39540. "
        "The device is running version 21.2R3-S5 and showing signs of PFE crashes. "
        "This can indicate exploitation through specific valid TCP traffic causing PFE crash. "
        "Please upgrade to version 21.2R3-S6 or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83000"
    )
