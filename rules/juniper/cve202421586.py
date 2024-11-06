from comfy import high

@high(
    name='rule_cve202421586',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware'
    )
)
def rule_cve202421586(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21586 vulnerability in Juniper Networks Junos OS on SRX Series
    and NFX Series devices. The vulnerability allows an unauthenticated, network-based attacker
    to cause a Denial-of-Service (DoS) condition by causing the PFE to crash and restart when
    specific valid traffic is received.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX or NFX Series
    chassis_output = commands.show_chassis_hardware
    if not any(platform in chassis_output for platform in ['SRX', 'NFX']):
        return

    # Extract version information
    version_output = commands.show_version

    # Versions before 21.4R1 are not affected
    if '21.4R1' not in version_output:
        return

    # List of vulnerable software versions for SRX Series
    srx_vulnerable_versions = [
        # 21.4 versions
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S7.8',
        # 22.1 versions
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3',
        '22.1R3-S4', '22.1R3-S5', '22.1R3-S5.2',
        # 22.2 versions
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4', '22.2R3-S4.10',
        # 22.3 versions
        '22.3R1', '22.3R2',
        # 22.4 versions
        '22.4R1', '22.4R2'
    ]

    # List of vulnerable software versions for NFX Series
    nfx_vulnerable_versions = [
        # 21.4 versions
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        # 22.1 versions after 22.1R1
        '22.1R2', '22.1R3',
        # 22.2 versions
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4',
        # 22.3 versions
        '22.3R1', '22.3R2',
        # 22.4 versions
        '22.4R1', '22.4R2'
    ]

    # Check if device is SRX or NFX and use appropriate version list
    if 'SRX' in chassis_output:
        vulnerable_versions = srx_vulnerable_versions
    else:  # NFX
        vulnerable_versions = nfx_vulnerable_versions

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    assert not version_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21586. "
        "The device is running a vulnerable version that can lead to PFE crash "
        "when processing specific valid traffic. "
        "Please upgrade to one of the following fixed versions: "
        "SRX Series: 21.4R3-S7.9, 22.1R3-S5.3, 22.2R3-S4.11, 22.3R3, 22.4R3, 23.2R1 or later; "
        "NFX Series: 21.4R3-S8, 22.2R3-S5, 22.3R3, 22.4R3, 23.2R1 or later. "
        "For more information, see https://supportportal.juniper.net/JSA83195"
    )
