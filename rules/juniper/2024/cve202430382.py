from comfy import high

@high(
    name='rule_cve202430382',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_cbf='show configuration | display set | match "policy-statement.*cos-next-hop-map"'
    )
)
def rule_cve202430382(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30382 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending specific routing updates that trigger memory corruption in rpd when CoS-based forwarding
    is configured.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S10 versions
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S8
        '21.2R3-S7', '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3',
        '21.2R3-S2', '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3
        '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3
        '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R2
        '22.1R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # Pre-21.2R3-S8-EVO versions
        '21.2R3-S7-EVO', '21.2R3-S6-EVO', '21.2R3-S5-EVO', '21.2R3-S4-EVO',
        '21.2R3-S3-EVO', '21.2R3-S2-EVO', '21.2R3-S1-EVO', '21.2R3-EVO',
        '21.2R2-EVO', '21.2R1-EVO',
        # 21.3 versions before 21.3R3-EVO
        '21.3R2-EVO', '21.3R1-EVO',
        # 21.4 versions before 21.4R3-EVO
        '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R2-EVO
        '22.1R1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if CoS-based forwarding with cos-next-hop-map is configured
    cbf_config = commands.show_config_cbf
    cbf_enabled = 'cos-next-hop-map' in cbf_config

    assert not cbf_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-30382. "
        "The device is running a vulnerable version with CoS-based forwarding (CBF) configured. "
        "This configuration can allow an attacker to cause rpd crash through specific routing updates. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 20.4R3-S10, 21.2R3-S8, 21.3R3, 21.4R3, 22.1R2, 22.2R1, or later; "
        "Junos OS Evolved: 21.2R3-S8-EVO, 21.3R3-EVO, 21.4R3-EVO, 22.1R2-EVO, 22.2R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA79174"
    )
