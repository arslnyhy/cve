from comfy import high

@high(
    name='rule_cve202447496',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_chassis_fpc='show chassis fpc'
    ),
)
def rule_cve202447496(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47496 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows a local, low-privileged attacker to cause a DoS condition
    by executing a specific command that crashes the Packet Forwarding Engine (PFE).
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        '22.3R3', '22.3R3-S1', '22.3R3-S2', '22.3R3-S3',
        '22.4R3', '22.4R3-S1',
        '23.2R1', '23.2R2',
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

    # Check for MPC1-MPC9 line cards
    fpc_output = commands.show_chassis_fpc
    has_vulnerable_mpcs = any('MPC' in line and any(f'MPC{i}' in line for i in range(1, 10)) 
                            for line in fpc_output.splitlines())

    # Assert that the device is not vulnerable
    assert not has_vulnerable_mpcs, (
        f"Device {device.name} is vulnerable to CVE-2024-47496. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with MPC1-MPC9 line cards, "
        "which makes it susceptible to PFE crashes through command execution. "
        "For more information, see https://supportportal.juniper.net/JSA88123"
    )
