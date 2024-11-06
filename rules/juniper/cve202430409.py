from comfy import medium

@medium(
    name='rule_cve202430409',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_telemetry='show configuration | display set | match "services analytics streaming"',
        show_fibtd_status='show system processes extensive | match fibtd'
    )
)
def rule_cve202430409(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30409 vulnerability in Juniper Networks Junos OS and Junos OS Evolved.
    The vulnerability allows an authenticated, network-based attacker to cause a Denial of Service (DoS)
    by causing the forwarding information base telemetry daemon (fibtd) to crash when telemetry
    subscription is active and Fib-streaming is enabled.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Extract version information
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 22.1 versions before 22.1R1-S2, 22.1R2
        '22.1R1', '22.1R1-S1'
    ]

    # Add EVO versions
    evo_vulnerable_versions = [
        # 22.1-EVO versions before 22.1R1-S2-EVO, 22.1R2-EVO
        '22.1R1-EVO', '22.1R1-S1-EVO'
    ]
    vulnerable_versions.extend(evo_vulnerable_versions)

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if telemetry streaming is configured
    telemetry_config = commands.show_config_telemetry
    telemetry_enabled = 'services analytics streaming' in telemetry_config

    if not telemetry_enabled:
        return

    # Check fibtd status for signs of high CPU or crashes
    fibtd_status = commands.show_fibtd_status
    fibtd_issues = any(
        indicator in fibtd_status.lower()
        for indicator in ['crashed', 'core', 'dumped', '100% cpu']
    )

    assert not fibtd_issues, (
        f"Device {device.name} is vulnerable to CVE-2024-30409. "
        "The device is running a vulnerable version with telemetry streaming enabled "
        "and showing signs of fibtd issues. This can indicate exploitation through "
        "malformed telemetry requests. "
        "Please upgrade to one of the following fixed versions: "
        "Junos OS: 22.1R1-S2, 22.1R2, 22.2R1, 22.2R2, 22.3R1, 22.4R1, or later; "
        "Junos OS Evolved: 22.1R1-S2-EVO, 22.1R2-EVO, 22.2R1-EVO, 22.2R2-EVO, "
        "22.3R1-EVO, 22.4R1-EVO, or later. "
        "For more information, see https://supportportal.juniper.net/JSA79099"
    )
