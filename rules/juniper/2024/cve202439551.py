from comfy import high

@high(
    name='rule_cve202439551',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_alg='show configuration | display set | match "security alg h323"',
        show_memory='show usp memory segment sha data objcache jsf'
    )
)
def rule_cve202439551(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39551 vulnerability in Juniper Networks Junos OS on SRX Series
    and MX Series with SPC3 and MS-MPC/MIC. The vulnerability allows an unauthenticated network-based
    attacker to cause a Denial of Service (DoS) through uncontrolled resource consumption in the
    H.323 ALG.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is SRX Series or MX Series with SPC3/MS-MPC/MIC
    chassis_output = commands.show_chassis_hardware
    if not ('SRX' in chassis_output or ('MX' in chassis_output and any(card in chassis_output for card in ['SPC3', 'MS-MPC', 'MS-MIC']))):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 20.4 versions before 20.4R3-S10
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S6
        '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2', '21.2R3-S1',
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3-S5
        '21.3R3-S4', '21.3R3-S3', '21.3R3-S2', '21.3R3-S1',
        '21.3R3', '21.3R2', '21.3R1',
        # 21.4 versions before 21.4R3-S6
        '21.4R3-S5', '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S2
        '22.2R3-S1', '22.2R3', '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2
        '23.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if H.323 ALG is enabled
    alg_config = commands.show_config_alg
    alg_enabled = 'security alg h323' in alg_config and 'disable' not in alg_config

    if not alg_enabled:
        return

    # Check for memory usage issues in JSF objcache
    memory_output = commands.show_memory
    memory_leak = False
    for line in memory_output.splitlines():
        if 'jsf' in line.lower():
            try:
                # Extract memory values (current and peak)
                values = line.split()
                current = int(values[3])
                peak = int(values[5])
                if current > 0.8 * peak:  # Memory usage > 80% of peak
                    memory_leak = True
                    break
            except (ValueError, IndexError):
                continue

    assert not memory_leak, (
        f"Device {device.name} is vulnerable to CVE-2024-39551. "
        "The device is running a vulnerable version with H.323 ALG enabled "
        "and showing signs of memory consumption in JSF objcache. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S10, 21.2R3-S6, 21.3R3-S5, 21.4R3-S6, 22.1R3-S4, 22.2R3-S2, "
        "22.3R3-S1, 22.4R3, 23.2R2, 23.4R1, or later. "
        "As a workaround, disable H.323 ALG until the device can be upgraded. "
        "For more information, see https://supportportal.juniper.net/JSA83013"
    )
