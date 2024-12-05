from comfy import medium

@medium(
    name='rule_cve202430390',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_services='show configuration | display set | match "system services (finger|ftp|netconf|ssh|telnet|xnm-clear-text|xnm-ssl|rest|tftp-server)"'
    )
)
def rule_cve202430390(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30390 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to cause a limited
    Denial of Service (DoS) to the management plane by exploiting incorrect connection limit
    enforcement when rate limits are triggered.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if device is running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-21.4R3-S4-EVO versions
        '21.4R3-S3-EVO', '21.4R3-S2-EVO', '21.4R3-S1-EVO',
        '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.1-EVO versions before 22.1R3-S3-EVO
        '22.1R3-S2-EVO', '22.1R3-S1-EVO', '22.1R3-EVO',
        '22.1R2-EVO', '22.1R1-EVO',
        # 22.2-EVO versions before 22.2R3-S2-EVO
        '22.2R3-S1-EVO', '22.2R3-EVO', '22.2R2-EVO', '22.2R1-EVO',
        # 22.3-EVO versions before 22.3R2-S1-EVO, 22.3R3-EVO
        '22.3R2-EVO', '22.3R1-EVO'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if any services have connection-limit or rate-limit configured
    services_config = commands.show_config_services
    services = [
        'finger', 'ftp', 'netconf', 'ssh', 'telnet',
        'xnm-clear-text', 'xnm-ssl', 'rest control', 'tftp-server'
    ]

    # Look for both explicit configuration and default settings
    has_limits = any(
        f"system services {service}" in services_config
        for service in services
    )

    assert not has_limits, (
        f"Device {device.name} is vulnerable to CVE-2024-30390. "
        "The device is running a vulnerable version of Junos OS Evolved with management services "
        "that have connection and rate limits (either configured or by default). This can allow "
        "an attacker to bypass connection limits when rate limits are triggered. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S9-EVO, 21.4R3-S4-EVO, 21.4R3-S6-EVO, 22.1R3-S3-EVO, 22.2R3-S2-EVO, "
        "22.3R2-S1-EVO, 22.3R3-EVO, 22.4R1-S2-EVO, 22.4R2-EVO, 22.4R3-EVO, 23.2R1-EVO, "
        "23.2R2-EVO, or later. "
        "As a workaround, use firewall filters to limit access to trusted hosts. "
        "For more information, see http://supportportal.juniper.net/JSA79183"
    )
