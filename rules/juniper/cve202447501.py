from comfy import medium

@medium(
    name='rule_cve202447501',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_vpls='show configuration | display set | match "routing-instances.*instance-type vpls"',
        show_config_satellite='show configuration | display set | match "chassis satellite-management"',
        show_fpc_crashes='show system core-dumps | match fpc'
    )
)
def rule_cve202447501(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47501 vulnerability in Juniper Networks Junos OS on MX304,
    MX with MPC10/11/LC9600, and EX9200 with EX9200-15C. The vulnerability allows a locally
    authenticated attacker with low privileges to cause a Denial of Service (DoS) by executing
    specific show commands that cause FPC crash in VPLS or Junos Fusion scenarios.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is affected platform
    chassis_output = commands.show_chassis_hardware
    affected_platforms = [
        'MX304',
        'MPC10', 'MPC11', 'LC9600',  # MX Series cards
        'EX9200-15C'  # EX9200 card
    ]
    if not any(platform in chassis_output for platform in affected_platforms):
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.2R3-S1
        '21.2R3', '21.2R2', '21.2R1',
        # 21.3 versions before 21.3R3
        '21.3R1', '21.3R2',
        # 21.4 versions before 21.4R2
        '21.4R1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if VPLS or Junos Fusion is configured
    vpls_config = commands.show_config_vpls
    satellite_config = commands.show_config_satellite

    vpls_enabled = 'instance-type vpls' in vpls_config
    fusion_enabled = 'chassis satellite-management' in satellite_config

    if not (vpls_enabled or fusion_enabled):
        return

    # Check for recent FPC crashes
    crash_output = commands.show_fpc_crashes
    recent_crashes = len([line for line in crash_output.splitlines() if 'fpc' in line])

    assert recent_crashes == 0, (
        f"Device {device.name} is vulnerable to CVE-2024-47501. "
        f"The device is running a vulnerable version with {'VPLS' if vpls_enabled else 'Junos Fusion'} configured "
        f"and has {recent_crashes} recent FPC crashes. This can indicate exploitation through "
        "specific show commands causing NULL pointer dereference. "
        "Please upgrade to one of the following fixed versions: "
        "21.2R3-S1, 21.3R3, 21.4R2, 22.1R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88131"
    )
