from comfy import high

@high(
    name='rule_cve202439531',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_ddos='show configuration | display set | match "system ddos-protection protocols.*aggregate (bandwidth|burst)"'
    )
)
def rule_cve202439531(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39531 vulnerability in Juniper Networks Junos OS Evolved on ACX 7000 Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through improper handling of DDoS protection values in the PFE, where protocol-specific settings affect
    other protocols sharing the same queue.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is ACX 7000 Series
    chassis_output = commands.show_chassis_hardware
    if not any(model in chassis_output for model in ['ACX7024', 'ACX7100', 'ACX7509']):
        return

    # Check if running Junos OS Evolved
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1 versions before 22.1R3-S6-EVO
        '22.1R3-S5-EVO', '22.1R3-S4-EVO', '22.1R3-S3-EVO', '22.1R3-S2-EVO',
        '22.1R3-S1-EVO', '22.1R3-EVO', '22.1R2-EVO', '22.1R1-EVO',
        # 22.2 versions before 22.2R3-S3-EVO
        '22.2R3-S2-EVO', '22.2R3-S1-EVO', '22.2R3-EVO',
        '22.2R2-EVO', '22.2R1-EVO',
        # 22.3 versions before 22.3R3-S3-EVO
        '22.3R3-S2-EVO', '22.3R3-S1-EVO', '22.3R3-EVO',
        '22.3R2-EVO', '22.3R1-EVO',
        # 22.4 versions before 22.4R3-S2-EVO
        '22.4R3-S1-EVO', '22.4R3-EVO', '22.4R2-EVO', '22.4R1-EVO',
        # 23.2 versions before 23.2R2-EVO
        '23.2R1-EVO',
        # 23.4 versions before 23.4R1-S1-EVO, 23.4R2-EVO
        '23.4R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if DDoS protection is configured with protocol-specific settings
    ddos_config = commands.show_config_ddos
    ddos_lines = ddos_config.splitlines()

    # Look for protocols with custom bandwidth/burst settings
    protocol_settings = {}
    for line in ddos_lines:
        if 'aggregate bandwidth' in line or 'aggregate burst' in line:
            parts = line.split()
            protocol = parts[parts.index('protocols') + 1]
            value = int(parts[-1])
            if protocol not in protocol_settings:
                protocol_settings[protocol] = []
            protocol_settings[protocol].append(value)

    # Device is vulnerable if multiple protocols have different settings
    has_custom_settings = len(protocol_settings) > 1

    assert not has_custom_settings, (
        f"Device {device.name} is vulnerable to CVE-2024-39531. "
        "The device is running a vulnerable version of Junos OS Evolved with protocol-specific "
        "DDoS protection settings. Due to a PFE vulnerability, these settings can affect other "
        "protocols sharing the same queue, potentially leading to DoS conditions. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S7-EVO, 22.1R3-S6-EVO, 22.2R3-S3-EVO, 22.3R3-S3-EVO, 22.4R3-S2-EVO, "
        "23.2R2-EVO, 23.4R1-S1-EVO, 23.4R2-EVO, 24.2R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA82991"
    )
