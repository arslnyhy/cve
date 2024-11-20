from comfy import high
import re


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

    srx_vulnerable_versions = [
        # 21.4 versions (before 21.4R3-S7.9)
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S7.8',
        # 22.1 versions (before 22.1R3-S5.3)
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3',
        '22.1R3-S4', '22.1R3-S5', '22.1R3-S5.1', '22.1R3-S5.2',
        # 22.2 versions (before 22.2R3-S4.11)
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4', '22.2R3-S4.10',
        # 22.3 versions (before 22.3R3)
        '22.3R1', '22.3R2',
        # 22.4 versions (before 22.4R3)
        '22.4R1', '22.4R2'
    ]

    nfx_vulnerable_versions = [
        # 21.4 versions (before 21.4R3-S8)
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7',
        # All 22.1 versions are affected
        '22.1R1', '22.1R2', '22.1R3',
        # 22.2 versions (before 22.2R3-S5)
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        '22.2R3-S4',
        # 22.3 versions (before 22.3R3)
        '22.3R1', '22.3R2',
        # 22.4 versions (before 22.4R3)
        '22.4R1', '22.4R2'
    ]

    # Check chassis hardware first
    chassis_output = commands.show_chassis_hardware

    # If not SRX or NFX, return early as device is not affected
    if not ('SRX' in chassis_output or 'NFX' in chassis_output):
        return True

    # Only check version if it's an SRX/NFX
    version_output = commands.show_version
    if is_version_vulnerable(version_output, srx_vulnerable_versions + nfx_vulnerable_versions):
        # If we get here, it's an SRX/NFX with a vulnerable version
        return False, (
            f"Device {device.name} is vulnerable to CVE-2024-21586. "
            "The device is running a vulnerable version that can lead to PFE crash "
            "when processing specific valid traffic. "
            "Please upgrade to one of the following fixed versions: "
            "SRX Series: 21.4R3-S7.9, 22.1R3-S5.3, 22.2R3-S4.11, 22.3R3, 22.4R3, 23.2R1 or later; "
            "NFX Series: 21.4R3-S8, 22.2R3-S5, 22.3R3, 22.4R3, 23.2R1 or later. "
            "For more information, see https://supportportal.juniper.net/JSA83195"
        )
    
    return True


def is_version_vulnerable(version_output, vulnerable_versions):
    # Extract version from the output (format: "Junos: 21.4R3")
    version_match = re.match(r'^Junos: (\d+\.\d+[^-\s]*)', version_output)
    if not version_match:
        return False
    
    device_version = version_match.group(1)
    return any(device_version.startswith(v) for v in vulnerable_versions)