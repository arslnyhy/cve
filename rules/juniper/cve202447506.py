from comfy import medium

@medium(
    name='rule_cve202447506',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_aamw='show configuration | display set | match "services advanced-anti-malware policy"',
        show_config_security='show configuration | display set | match "security policies.*then permit application-services advanced-anti-malware-policy"',
        show_pfe_crashes='show system core-dumps | match pfe'
    )
)
def rule_cve202447506(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47506 vulnerability in Juniper Networks Junos OS on SRX Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending traffic that triggers a deadlock in ATP Cloud inspection, leading to PFE crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    if 'SRX' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.3R3-S1
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3
        '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R2
        '22.1R1',
        # 22.2 versions before 22.2R1-S2, 22.2R2
        '22.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if ATP Cloud inspection is configured
    aamw_config = commands.show_config_aamw
    security_config = commands.show_config_security

    aamw_policy = 'services advanced-anti-malware policy' in aamw_config
    aamw_enabled = 'then permit application-services advanced-anti-malware-policy' in security_config

    if not (aamw_policy and aamw_enabled):
        return

    # Check for recent PFE crashes
    crash_output = commands.show_pfe_crashes
    recent_crashes = 'pfe' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-47506. "
        "The device is running a vulnerable version with ATP Cloud inspection enabled "
        f"and has {recent_crashes} recent PFE crashes. This can indicate exploitation "
        "through traffic causing deadlock in ATP Cloud inspection. "
        "Please upgrade to one of the following fixed versions: "
        "21.3R3-S1, 21.4R3, 22.1R2, 22.2R1-S2, 22.2R2, 22.3R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88137"
    )
