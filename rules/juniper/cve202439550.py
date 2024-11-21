from comfy import medium

@medium(
    name='rule_cve202439550',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_interfaces='show interfaces terse',
        show_rtlog_memory='show system processes extensive | match rtlog'
    )
)
def rule_cve202439550(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39550 vulnerability in Juniper Networks Junos OS on MX Series.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS)
    through memory leak in rtlogd process when port flaps occur.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with SPC3
    chassis_output = commands.show_chassis_hardware
    if not ('MX' in chassis_output and 'SPC3' in chassis_output):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2R3 versions before 21.2R3-S8
        '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4',
        '21.2R3-S5', '21.2R3-S6', '21.2R3-S7',
        # 21.4 versions from R2 before 21.4R3-S6
        '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3',
        '21.4R3-S4', '21.4R3-S5',
        # 22.1 versions before 22.1R3-S5
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2',
        '22.1R3-S3', '22.1R3-S4',
        # 22.2 versions before 22.2R3-S3
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2',
        # 22.3 versions before 22.3R3-S2
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1',
        # 22.4 versions before 22.4R3-S1
        '22.4R1', '22.4R2', '22.4R3',
        # 23.2 versions before 23.2R2
        '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for interface flaps
    interface_output = commands.show_interfaces
    flapping_interfaces = 'down' in interface_output

    # Check rtlogd memory usage
    rtlog_output = commands.show_rtlog_memory
    high_memory = False
    for line in rtlog_output.splitlines():
        if 'rtlogd' in line:
            try:
                # Extract memory values (current and peak)
                values = line.split()
                current = int(values[3])
                peak = int(values[5])
                if current > 0.8 * peak:  # Memory usage > 80% of peak
                    high_memory = True
                    break
            except (ValueError, IndexError):
                continue

    # Device is vulnerable if showing signs of memory leak and has flapping interfaces
    is_vulnerable = high_memory and flapping_interfaces

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39550. "
        "The device is running a vulnerable version and showing signs of rtlogd memory leak "
        f"with {flapping_interfaces} flapping interfaces. Memory can only be recovered by "
        "manually restarting rtlogd process. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S8, 21.4R3-S6, 22.1R3-S5, 22.2R3-S3, 22.3R3-S2, 22.4R3-S1, "
        "23.2R2, 23.4R2, 24.2R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA83012"
    )
