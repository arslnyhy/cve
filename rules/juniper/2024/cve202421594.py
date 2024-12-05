from comfy import medium

@medium(
    name='rule_cve202421594',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_security_policies='request security policies check'
    )
)
def rule_cve202421594(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21594 vulnerability in Juniper Networks Junos OS SRX 5000 Series.
    The vulnerability allows an authenticated, low privileged, local attacker to cause a Denial of
    Service (DoS) by repeatedly executing a specific CLI command that leads to memory corruption
    and Flow Processing Daemon (flowd) crash.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX 5000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['SRX5400', 'SRX5600', 'SRX5800']):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S6 versions
        '20.4R3-S5', '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        '20.4R2', '20.4R1',
        # 21.1 versions before 21.1R3-S5
        '21.1R3-S4', '21.1R3-S3', '21.1R3-S2', '21.1R3-S1', '21.1R3',
        '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R3-S4
        '21.2R3-S3', '21.2R3-S2', '21.2R3-S1', '21.2R3',
        '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S3
        '21.3R3-S2', '21.3R3-S1', '21.3R3',
        '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S3
        '21.4R3-S2', '21.4R3-S1', '21.4R3',
        '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S1
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R2
        '22.3R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for error message indicating policy sync issues
    policy_output = commands.show_security_policies
    policy_error = 'policies are out of sync for PFE node' in policy_output

    assert not policy_error, (
        f"Device {device.name} is vulnerable to CVE-2024-21594. "
        "The device is running a vulnerable version and showing signs of policy sync issues "
        "which could lead to flowd crashes. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S6, 21.1R3-S5, 21.2R3-S4, 21.3R3-S3, 21.3R3-S4, 21.4R3-S3, "
        "22.1R3-S1, 22.2R3, 22.3R2, 22.4R1, 22.4R2, 23.1R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA75733"
    )
