from comfy import high

@high(
    name='rule_cve202421589',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_configuration='show configuration | display set | match "services active-assurance"'
    )
)
def rule_cve202421589(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-21589 vulnerability in Juniper Networks Paragon Active Assurance.
    The vulnerability allows an unauthenticated network-based attacker to access reports without
    authenticating, potentially exposing sensitive configuration information.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if Paragon Active Assurance is configured
    config_output = commands.show_configuration
    if 'services active-assurance' not in config_output:
        return

    # Extract version information
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 3.1.x versions
        '3.1.0',
        # 3.2.x versions
        '3.2.0', '3.2.2',
        # 3.3.x versions
        '3.3.0', '3.3.1',
        # 3.4.x versions
        '3.4.0'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # Check if it's a SaaS deployment (not affected)
    is_saas = 'saas-mode' in config_output

    # Device is vulnerable if running affected version and not in SaaS mode
    is_vulnerable = version_vulnerable and not is_saas

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-21589. "
        "The device is running a vulnerable version of Paragon Active Assurance "
        "that allows unauthenticated access to reports containing sensitive configuration information. "
        "Please upgrade to one of the following fixed versions: "
        "3.1.2, 3.2.3, 3.3.2, 3.4.1, 4.0.0, 4.1.0 or later. "
        "For more information, see https://supportportal.juniper.net/JSA75727"
    )
