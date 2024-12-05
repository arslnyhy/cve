from comfy import high

@high(
    name='rule_cve202439518',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_telemetry='show configuration | display set | match "services analytics streaming"',
        show_sensord_memory='show system processes extensive | match sensord'
    )
)
def rule_cve202439518(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39518 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    through a memory leak in the telemetry sensor process (sensord) when specific telemetry subscriptions
    are active.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with MPC10E
    chassis_output = commands.show_chassis_hardware
    if not ('MX' in chassis_output and any(model in chassis_output for model in ['MX240', 'MX480', 'MX960'])):
        return
    if 'MPC10E' not in chassis_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions from 21.2R3-S5 before 21.2R3-S7
        '21.2R3-S5', '21.2R3-S6',
        # 21.4 versions from 21.4R3-S4 before 21.4R3-S6
        '21.4R3-S4', '21.4R3-S5',
        # 22.2 versions from 22.2R3 before 22.2R3-S4
        '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        # 22.3 versions from 22.3R2 before 22.3R3-S2
        '22.3R2', '22.3R3', '22.3R3-S1',
        # 22.4 versions from 22.4R1 before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if telemetry streaming is configured
    telemetry_config = commands.show_config_telemetry
    telemetry_enabled = 'services analytics streaming' in telemetry_config

    if not telemetry_enabled:
        return

    # Check sensord memory utilization
    memory_output = commands.show_sensord_memory
    for line in memory_output.splitlines():
        if 'sensord' in line:
            try:
                # Extract memory values (in MB)
                parts = line.split()
                current_mem = float(parts[2].replace('MB', ''))
                peak_mem = float(parts[3].replace('MB', ''))
                
                # Alert if memory usage is high (>800MB) or growing (>90% of peak)
                memory_leak_detected = current_mem > 800 or (peak_mem > 0 and current_mem > 0.9 * peak_mem)
                
                assert not memory_leak_detected, (
                    f"Device {device.name} is vulnerable to CVE-2024-39518. "
                    f"The device is running a vulnerable version with telemetry streaming enabled "
                    f"and showing signs of sensord memory leak (Current: {current_mem}MB, Peak: {peak_mem}MB). "
                    "Please upgrade to one of the following fixed versions: "
                    "21.2R3-S7, 21.4R3-S6, 22.2R3-S4, 22.3R3-S2, 22.4R3, 23.2R2, 23.4R1, or later. "
                    "There are no known workarounds for this issue. "
                    "For more information, see https://supportportal.juniper.net/JSA82982"
                )
            except (ValueError, IndexError):
                continue
