from comfy import medium

@medium(
    name='rule_cve202439517',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_evpn='show configuration | display set | match "protocols evpn"',
        show_config_vxlan='show configuration | display set | match "(vlans.*vxlan|routing-instances.*vxlan)"',
    )
)
def rule_cve202439517(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39517 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an unauthenticated, adjacent attacker to cause Denial of Service (DoS)
    by sending specific L2 packets that cause rpd to hang in devices with EVPN/VXLAN configured.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.4R3-S7 versions
        '21.4R3-S6', '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2',
        '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S5
        '22.1R3-S4', '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S3
        '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S2
        '22.4R3-S1', '22.4R3', '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1',
        # 23.4 versions before 23.4R1-S1
        '23.4R1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [f"{ver}-EVO" for ver in vulnerable_versions]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if EVPN is configured
    evpn_config = commands.show_config_evpn
    evpn_enabled = 'protocols evpn' in evpn_config

    if not evpn_enabled:
        return

    # Check if VXLAN is configured
    vxlan_config = commands.show_config_vxlan
    vxlan_enabled = 'vxlan' in vxlan_config

    if not vxlan_enabled:
        return

    assert not vxlan_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-39517. "
        "The device is running a vulnerable version with EVPN/VXLAN configured "
        "and showing signs of rpd high CPU utilization. This can indicate exploitation "
        "through specific L2 packets causing rpd to hang. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.4R3-S7, 22.1R3-S5, 22.2R3-S3, 22.3R3-S3, 22.4R3-S2, 23.2R2, "
        "23.4R1-S1, 23.4R2, 24.2R1 or later; "
        "Junos OS Evolved: corresponding EVO versions. "
        "For more information, see https://supportportal.juniper.net/JSA79175"
    )
