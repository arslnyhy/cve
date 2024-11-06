from comfy import high

@high(
    name='rule_cve202439562',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_processes='show system processes | match sshd',
        show_config_ssh='show configuration | display set | match "system services ssh"',
        show_config_filter='show configuration | display set | match "firewall filter.*from source-address-filter"'
    )
)
def rule_cve202439562(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-39562 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated network-based attacker to cause a Denial of Service (DoS)
    by sending a high rate of SSH connections that cause xinetd to crash and leave defunct sshd processes.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # Check if running Junos OS Evolved
    version_output = commands.show_version
    if 'Evolved' not in version_output:
        return

    # List of vulnerable software versions
    vulnerable_versions = [
        # All versions before 21.4R3-S7-EVO
        '21.4R3-S6-EVO', '21.4R3-S5-EVO', '21.4R3-S4-EVO', '21.4R3-S3-EVO',
        '21.4R3-S2-EVO', '21.4R3-S1-EVO', '21.4R3-EVO', '21.4R2-EVO', '21.4R1-EVO',
        # 22.3-EVO versions before 22.3R2-S2-EVO, 22.3R3-S2-EVO
        '22.3R1-EVO', '22.3R2-EVO', '22.3R2-S1-EVO', '22.3R3-EVO', '22.3R3-S1-EVO',
        # 22.4-EVO versions before 22.4R3-EVO
        '22.4R1-EVO', '22.4R2-EVO',
        # 23.2-EVO versions before 23.2R2-EVO
        '23.2R1-EVO'
    ]

    # Check if version is vulnerable (22.1-EVO and 22.2-EVO are not affected)
    if any(ver in version_output for ver in ['22.1-EVO', '22.2-EVO']):
        return

    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if SSH is enabled
    ssh_config = commands.show_config_ssh
    ssh_enabled = 'system services ssh' in ssh_config

    if not ssh_enabled:
        return

    # Check for firewall filter protecting SSH access
    filter_config = commands.show_config_filter
    ssh_protected = 'firewall filter' in filter_config and 'source-address-filter' in filter_config

    # Check for defunct sshd processes
    processes = commands.show_processes
    defunct_count = len([line for line in processes.splitlines() if '[sshd] <defunct>' in line])

    # Device is vulnerable if SSH is enabled without source filtering and showing defunct processes
    is_vulnerable = not ssh_protected and defunct_count > 0

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-39562. "
        f"The device is running a vulnerable version with {defunct_count} defunct sshd processes "
        "and SSH enabled without source address filtering. This can allow an attacker to cause "
        "SSH service outage through xinetd crashes. "
        "Please upgrade to one of the following fixed versions: "
        "21.4R3-S7-EVO, 22.2R1-EVO, 22.3R2-S2-EVO, 22.3R3-S2-EVO, 22.4R3-EVO, "
        "23.2R2-EVO, 23.4R1-EVO, or later. "
        "As a workaround, configure firewall filters to limit SSH access to trusted hosts. "
        "If service is disrupted, run: systemctl restart xinetd-external.service "
        "For more information, see https://supportportal.juniper.net/JSA75724"
    )
