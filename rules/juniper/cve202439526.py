from comfy import medium

@medium(
    name='rule_cve202439526',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_dhcp='show configuration | display set | match "(forwarding-options dhcp-relay|system services dhcp-local-server)"',
        show_log_messages='show log messages | match "Wedge-Detect.*Host Loopback"'
    )
)
def rule_cve202439526(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39526 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an attacker to cause a Denial of Service (DoS) by sending malformed DHCP
    packets that cause ingress packet processing to stop when DHCP snooping is enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is affected platform
    chassis_output = commands.show_chassis_hardware
    
    # Check for MX Series with specific line cards
    mx_affected = ('MX' in chassis_output and 
                  any(card in chassis_output for card in ['MPC10', 'MPC11', 'LC9600', 'MX304']))
    
    # Check for EX9200 with specific line card
    ex_affected = 'EX9200' in chassis_output and 'EX9200-15C' in chassis_output
    
    # Check for PTX Series with Junos OS Evolved
    version_output = commands.show_version
    ptx_affected = 'PTX' in chassis_output and 'Evolved' in version_output

    if not (mx_affected or ex_affected or ptx_affected):
        return

    # List of vulnerable software versions for Junos OS
    junos_vulnerable_versions = [
        # All versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # All versions of 22.3
        '22.3R1', '22.3R2', '22.3R3',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # List of vulnerable software versions for Junos OS Evolved
    evo_vulnerable_versions = [
        # 19.3R1-EVO through 21.2R3-S7-EVO
        '19.3R1-EVO', '21.2R3-S7-EVO',
        # 21.4-EVO before 21.4R3-S7-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '21.4R3-S4-EVO', '21.4R3-S5-EVO', '21.4R3-S6-EVO',
        # 22.1-EVO before 22.1R3-S6-EVO
        '22.1R1-EVO', '22.1R2-EVO', '22.1R3-EVO',
        '22.1R3-S1-EVO', '22.1R3-S2-EVO', '22.1R3-S3-EVO',
        '22.1R3-S4-EVO', '22.1R3-S5-EVO',
        # 22.2-EVO before 22.2R3-S5-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO', '22.2R3-S3-EVO', '22.2R3-S4-EVO',
        # 22.3-EVO before 22.3R3-S3-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO',
        '22.3R3-S1-EVO', '22.3R3-S2-EVO',
        # 22.4-EVO before 22.4R3-S1-EVO
        '22.4R1-EVO', '22.4R2-EVO', '22.4R3-EVO',
        # 23.2-EVO before 23.2R2-S2-EVO
        '23.2R1-EVO', '23.2R2-EVO', '23.2R2-S1-EVO',
        # 23.4-EVO before 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    vulnerable_versions = evo_vulnerable_versions if 'Evolved' in version_output else junos_vulnerable_versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if DHCP snooping is enabled
    dhcp_config = commands.show_config_dhcp
    dhcp_enabled = any(config in dhcp_config for config in [
        'forwarding-options dhcp-relay',
        'system services dhcp-local-server'
    ])

    if not dhcp_enabled:
        return

    # Check for wedge detection errors in logs
    log_output = commands.show_log_messages
    wedge_detected = 'Wedge-Detect : Host Loopback Wedge Detected' in log_output

    assert not wedge_detected, (
        f"Device {device.name} is vulnerable to CVE-2024-39526. "
        "The device is running a vulnerable version with DHCP snooping enabled "
        "and showing signs of interface wedging through malformed DHCP packets. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 21.2R3-S7, 21.4R3-S6, 22.2R3-S3, 22.4R3, 23.2R2, 23.4R2, 24.2R1 or later; "
        "Junos OS Evolved: 21.2R3-S8-EVO, 21.4R3-S7-EVO, 22.1R3-S6-EVO, 22.2R3-S5-EVO, "
        "22.3R3-S3-EVO, 22.4R3-S1-EVO, 23.2R2-S2-EVO, 23.4R2-EVO, 24.2R1-EVO or later. "
        "For more information, see https://supportportal.juniper.net/JSA88103"
    )
