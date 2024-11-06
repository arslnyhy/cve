from comfy import medium

@medium(
    name='rule_cve202430391',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ipsec='show configuration | display set | match "security ipsec proposal.*authentication-algorithm"'
    )
)
def rule_cve202430391(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30391 vulnerability in Juniper Networks Junos OS on MX Series
    with SPC3 and SRX Series. The vulnerability allows an unauthenticated network-based attacker
    to cause limited impact to integrity/availability when IPsec is configured with hmac-sha-384
    or hmac-sha-512 authentication algorithms.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with SPC3 or SRX Series
    chassis_output = commands.show_chassis_hardware
    if not ('SRX' in chassis_output or ('MX' in chassis_output and 'SPC3' in chassis_output)):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S7 versions
        '20.4R3-S6', '20.4R3-S5', '20.4R3-S4', '20.4R3-S3',
        '20.4R3-S2', '20.4R3-S1', '20.4R3', '20.4R2', '20.4R1',
        # 21.1 versions before 21.1R3
        '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R2-S1, 21.2R3
        '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R1-S2, 21.3R2
        '21.3R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if IPsec is configured with hmac-sha-384 or hmac-sha-512
    ipsec_config = commands.show_config_ipsec
    vulnerable_auth = any(auth in ipsec_config for auth in [
        'authentication-algorithm hmac-sha-384',
        'authentication-algorithm hmac-sha-512'
    ])

    assert not vulnerable_auth, (
        f"Device {device.name} is vulnerable to CVE-2024-30391. "
        "The device is running a vulnerable version with IPsec configured to use hmac-sha-384 "
        "or hmac-sha-512 authentication. This configuration results in no authentication being "
        "performed for tunnel traffic. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S7, 21.1R3, 21.2R2-S1, 21.2R3, 21.3R1-S2, 21.3R2, 21.4R1, or later. "
        "Note: For releases earlier than 21.1, the affected CLI options have been removed. "
        "For more information, see http://supportportal.juniper.net/JSA79188"
    )
