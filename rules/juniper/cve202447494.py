from comfy import medium

@medium(
    name='rule_cve202447494',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_analytics='show configuration | display set | match "services analytics"',
        show_fpc_crashes='show system core-dumps | match fpc'
    )
)
def rule_cve202447494(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-47494 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an attacker who is already causing impact to established sessions
    to trigger a race condition in AgentD process during telemetry polling, leading to memory
    corruption and FPC crash (DoS).

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S9
        '21.4R3-S8', '21.4R3-S7', '21.4R3-S6', '21.4R3-S5', '21.4R3-S4',
        '21.4R3-S3', '21.4R3-S2', '21.4R3-S1', '21.4R3', '21.4R2', '21.4R1',
        # 22.2 versions before 22.2R3-S5
        '22.2R3-S4', '22.2R3-S3', '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S4
        '22.3R3-S3', '22.3R3-S2', '22.3R3-S1', '22.3R3',
        '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3-S3
        '22.4R3-S2', '22.4R3-S1', '22.4R3',
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R2-S2
        '23.2R2-S1', '23.2R2', '23.2R1',
        # 23.4 versions before 23.4R2
        '23.4R1'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if analytics services are configured
    analytics_config = commands.show_config_analytics
    analytics_enabled = 'services analytics' in analytics_config

    if not analytics_enabled:
        return

    # Check for recent FPC crashes
    crash_output = commands.show_fpc_crashes
    recent_crashes = 'fpc' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-47494. "
        "The device is running a vulnerable version with analytics services enabled "
        f"and has {recent_crashes} recent FPC crashes. This can indicate exploitation "
        "through a race condition in AgentD process during telemetry polling. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S9, 22.2R3-S5, 22.3R3-S4, 22.4R3-S3, 23.2R2-S2, 23.4R2, 24.2R1, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA88121"
    )
