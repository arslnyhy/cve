from comfy import high

@high(
    name='rule_cve20242432',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info'
    ),
)
def rule_cve20242432(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-2432 vulnerability in Palo Alto Networks GlobalProtect App.
    The vulnerability allows a local user to execute programs with elevated privileges due to a race condition.
    The test checks if the GlobalProtect app version is vulnerable.
    """
    # Extract the system information from the command output
    system_info_output = commands.show_system_info

    # Define the minimum non-vulnerable versions
    non_vulnerable_versions = {
        '6.2': '6.2.1',
        '6.1': '6.1.2',
        '6.0': '6.0.8',
        '5.1': '5.1.12'
    }

    # Check if the current version is vulnerable
    is_vulnerable = False
    for major_version, min_version in non_vulnerable_versions.items():
        if major_version in system_info_output:
            current_version = system_info_output.split()[-1]
            if current_version < min_version:
                is_vulnerable = True
                break

    # If version is not vulnerable, exit early
    if not is_vulnerable:
        return

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-2432. "
        "The GlobalProtect app is running a version that is susceptible to privilege escalation. "
        "For more information, see the Palo Alto Networks Security Advisory."
    )
