from comfy import medium

@medium(
    name='rule_cve202430401',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_fpc_crashes='show system core-dumps | match fpc',
        show_aftman_status='show system processes extensive | match aftman'
    )
)
def rule_cve202430401(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30401 vulnerability in Juniper Networks Junos OS on MX Series
    with MPC10E, MPC11, MX10K-LC9600 line cards, MX304, and EX9200-15C. The vulnerability allows
    an attacker to exploit a stack-based buffer overflow in aftman process, leading to FPC reboot.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is MX Series with affected line cards or EX9200-15C
    chassis_output = commands.show_chassis_hardware
    affected_cards = ['MPC10E', 'MPC11', 'MX10K-LC9600', 'MX304']
    if not (
        ('MX' in chassis_output and any(card in chassis_output for card in affected_cards)) or
        'EX9200-15C' in chassis_output
    ):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.2 versions before 21.2R3-S1
        '21.2R1', '21.2R2', '21.2R3',
        # 21.4 versions before 21.4R3
        '21.4R1', '21.4R2',
        # 22.1 versions before 22.1R2
        '22.1R1',
        # 22.2 versions before 22.2R2
        '22.2R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check for signs of aftman issues and FPC crashes
    fpc_crashes = commands.show_fpc_crashes
    aftman_status = commands.show_aftman_status

    # Look for recent FPC crashes or aftman issues
    recent_crashes = len([line for line in fpc_crashes.splitlines() if 'fpc' in line])
    aftman_issues = any(
        indicator in aftman_status.lower()
        for indicator in ['crash', 'killed', 'core', 'dumped']
    )

    # Device shows signs of vulnerability if either condition is true
    stability_issues = recent_crashes > 0 or aftman_issues

    assert not stability_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30401. "
        "The device is running a vulnerable version and showing signs of aftman/FPC instability. "
        "This can indicate exploitation of the stack-based buffer overflow vulnerability. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S1, 21.4R3, 22.1R2, 22.2R2, 22.3R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA79110"
    )
