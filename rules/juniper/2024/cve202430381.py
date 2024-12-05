from comfy import high

@high(
    name='rule_cve202430381',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_paa='show configuration | display set | match "services active-assurance"',
        show_config_firewall='show configuration | display set | match "firewall filter.*from source-address"'
    )
)
def rule_cve202430381(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30381 vulnerability in Juniper Networks Paragon Active Assurance.
    The vulnerability allows a network-adjacent attacker with root access to a Test Agent Appliance
    to access sensitive information about downstream devices through exposed internal database objects.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if Paragon Active Assurance is configured
    paa_config = commands.show_config_paa
    if 'services active-assurance' not in paa_config:
        return

    # Extract version information
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.1.x versions
        '4.1.0',
        # 4.2.x versions before 4.2.1
        '4.2.0'
    ]

    # Check if version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if firewall filters are configured to protect Control Center
    firewall_config = commands.show_config_firewall
    
    # Look for source address restrictions in firewall filters
    protected = any(
        'source-address' in line and ('test-agent' in line.lower() or 'admin' in line.lower())
        for line in firewall_config.splitlines()
    )

    assert protected, (
        f"Device {device.name} is vulnerable to CVE-2024-30381. "
        "The device is running a vulnerable version of Paragon Active Assurance without proper "
        "firewall filters to restrict access to the Control Center. This can allow an attacker "
        "with root access to a Test Agent to access sensitive information through exposed database objects. "
        "Please upgrade to one of the following fixed versions: "
        "4.2.1, 4.3.0, or later. "
        "As a workaround, configure firewall filters to limit access to trusted Test Agents and administrators. "
        "For more information, see https://supportportal.juniper.net/JSA79173"
    )
