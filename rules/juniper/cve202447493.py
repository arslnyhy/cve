from comfy import high

@high(
    name='rule_cve202447493',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_chassis_fpc='show chassis fpc'
    ),
)
def rule_cve202447493(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47493 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a DoS condition
    through memory leaks in the PFE when using channelized MICs on MX Series platforms.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6',
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5',
        '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3', '22.1R3-S4',
        '22.2R3', '22.2R3-S1', '22.2R3-S2',
        '22.3R3', '22.3R3-S1',
        '22.4R3',
        '23.2R1',
        '23.4R1'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if not is_mx_platform:
        return

    # Check for high memory utilization in FPCs
    fpc_output = commands.show_chassis_fpc
    high_memory = any(line for line in fpc_output.splitlines() if 'Online' in line and int(line.split()[-2]) > 80)

    # Assert that the device is not vulnerable
    assert not high_memory, (
        f"Device {device.name} is vulnerable to CVE-2024-47493. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with high FPC memory utilization, "
        "which indicates potential memory leaks from channelized MIC interface flaps. "
        "For more information, see https://supportportal.juniper.net/JSA88119"
    )
