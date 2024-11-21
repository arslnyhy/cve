from comfy import high

@high(
    name='rule_cve202439553',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_flow='show configuration | display set | match "services flow-monitoring"',
        show_config_sampling='show configuration | display set | match "forwarding-options sampling"',
        show_msvcs_crashes='show system core-dumps | match msvcsd'
    )
)
def rule_cve202439553(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39553 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a Denial of Service (DoS)
    by sending arbitrary data that causes msvcsd process to crash when inline jflow is configured.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 21.4 versions before 21.4R3-S7-EVO
        '21.4R1-EVO', '21.4R2-EVO', '21.4R3-EVO',
        '21.4R3-S1-EVO', '21.4R3-S2-EVO', '21.4R3-S3-EVO',
        '21.4R3-S4-EVO', '21.4R3-S5-EVO', '21.4R3-S6-EVO',
        # 22.2 versions before 22.2R3-S3-EVO
        '22.2R1-EVO', '22.2R2-EVO', '22.2R3-EVO',
        '22.2R3-S1-EVO', '22.2R3-S2-EVO',
        # 22.3 versions before 22.3R3-S2-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R3-EVO',
        '22.3R3-S1-EVO',
        # 22.4 versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2 versions before 23.2R1-S2-EVO, 23.2R2-EVO
        '23.2R1-EVO', '23.2R1-S1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if inline jflow is configured
    flow_config = commands.show_config_flow
    sampling_config = commands.show_config_sampling

    # Check for required configuration elements
    required_config = [
        'services flow-monitoring version-ipfix' in flow_config or 'services flow-monitoring version9' in flow_config,
        'forwarding-options sampling instance' in sampling_config,
        'input rate' in sampling_config,
        'output flow-server' in sampling_config,
        'inline-jflow source-address' in sampling_config
    ]

    jflow_configured = all(required_config)

    if not jflow_configured:
        return

    # Check for recent msvcsd crashes
    crash_output = commands.show_msvcs_crashes
    recent_crashes = 'msvcsd' in crash_output

    assert not recent_crashes, (
        f"Device {device.name} is vulnerable to CVE-2024-39553. "
        "The device is running a vulnerable version with inline jflow configured "
        f"and has {recent_crashes} recent msvcsd crashes. This can indicate exploitation "
        "through arbitrary data sent to the sampling service. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S7-EVO, 22.2R3-S3-EVO, 22.3R3-S2-EVO, 22.4R3-EVO, 23.2R1-S2-EVO, "
        "23.2R2-EVO, 23.4R1-EVO, or later. "
        "There are no known workarounds for this issue. "
        "For more information, see https://supportportal.juniper.net/JSA79101"
    )
