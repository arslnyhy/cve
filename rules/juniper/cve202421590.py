from comfy import medium

@medium(
    name='rule_cve202421590',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_mpls_config='show configuration | display set | match "protocols mpls"'
    )
)
def rule_cve202421590(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21590 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated attacker within the MPLS administrative domain
    to send specifically crafted packets to the Routing Engine (RE) to cause a Denial of Service (DoS).

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions before 21.2R3-S8-EVO
        '21.2R1-EVO', '21.2R2-EVO', '21.2R3-EVO', '21.2R3-S1-EVO', '21.2R3-S2-EVO',
        '21.2R3-S3-EVO', '21.2R3-S4-EVO', '21.2R3-S5-EVO', '21.2R3-S6-EVO', '21.2R3-S7-EVO',
        # 21.4 versions before 21.4R3-S6-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO', '21.4R3-S1-EVO', '21.4R3-S2-EVO',
        '21.4R3-S3-EVO', '21.4R3-S4-EVO', '21.4R3-S5-EVO',
        # 22.2 versions before 22.2R3-S4-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO', '22.2R3-S1-EVO', '22.2R3-S2-EVO',
        '22.2R3-S3-EVO',
        # 22.3 versions before 22.3R3-S3-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO', '22.3R3-S1-EVO', '22.3R3-S2-EVO',
        # 22.4 versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2 versions before 23.2R2-EVO
        '23.2R1-EVO',
        # 23.4 versions before 23.4R1-S1-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if MPLS is configured
    mpls_config = commands.show_mpls_config
    mpls_enabled = 'protocols mpls' in mpls_config

    assert not mpls_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-21590. "
        "The device is running a vulnerable version of Junos OS Evolved with MPLS enabled. "
        "This configuration can allow specifically crafted MPLS IPv4 packets to reach the RE "
        "and cause a sustained Denial of Service condition. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8-EVO, 21.4R3-S6-EVO, 22.2R3-S4-EVO, 22.3R3-S3-EVO, 22.4R3-EVO, "
        "23.2R2-EVO, 23.4R1-S1-EVO, 24.1R1-EVO or later. "
        "For more information, see https://supportportal.juniper.net/JSA75728"
    )
