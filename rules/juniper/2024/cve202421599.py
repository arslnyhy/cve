from comfy import medium

@medium(
    name='rule_cve202421599',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ptp='show configuration | display set | match "protocols ptp"',
        show_heap='show heap',
        show_clksync='show clksync ptp nbr-upd-info'
    )
)
def rule_cve202421599(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21599 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS)
    by sending PTP packets to an MPC3E that doesn't support PTP, causing memory leak and eventual
    MPC crash and restart.
    """
    # Check if device is MX Series with MPC3E
    chassis_output = commands.show_chassis_hardware
    if not ('MX' in chassis_output and 'MPC3E' in chassis_output):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S3 versions
        '20.4R3-S2', '20.4R3-S1', '20.4R3', '20.4R2', '20.4R1',
        # 21.1 versions before 21.1R3-S4
        '21.1R3-S3', '21.1R3-S2', '21.1R3-S1', '21.1R3',
        '21.1R2', '21.1R1',
        # 21.2 versions before 21.2R3
        '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R2-S1, 21.3R3
        '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R2
        '21.4R1',
        # 22.1 versions before 22.1R2
        '22.1R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if PTP is configured on any interface
    ptp_config = commands.show_config_ptp
    ptp_enabled = 'protocols ptp' in ptp_config

    if not ptp_enabled:
        return

    # Check for memory leak indicators
    heap_output = commands.show_heap
    clksync_output = commands.show_clksync

    lan_buffer_high = 'LAN buffer' in heap_output  # Increase in LAN buffer utilization
    pending_pfes = 'Pending PFEs' in clksync_output  # Non-zero Pending PFEs counter

    # Device shows signs of memory leak if both indicators are present
    memory_leak_signs = lan_buffer_high and pending_pfes

    assert not memory_leak_signs, (
        f"Device {device.name} is vulnerable to CVE-2024-21599. "
        "The device is running a vulnerable version with PTP configured on MPC3E "
        "and showing signs of memory leak (high LAN buffer utilization and pending PFEs). "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S3, 21.1R3-S4, 21.2R3, 21.3R2-S1, 21.3R3, 21.4R2, 22.1R2, 22.2R1, or later. "
        "As a temporary measure, you can recover leaked memory by: deactivate protocol ptp; commit; activate protocol ptp; commit. "
        "For more information, see https://supportportal.juniper.net/JSA75740"
    )
