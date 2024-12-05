from comfy import high

@high(
    name='rule_cve20242431',
    platform=['paloalto_panos'],
    commands=dict(
        show_system_info='show system info',
        show_globalprotect_config='show globalprotect config'
    ),
)
def rule_cve20242431(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-2431 vulnerability in Palo Alto Networks GlobalProtect App.
    The vulnerability allows a non-privileged user to disable the GlobalProtect app without needing
    the passcode in configurations that allow a user to disable GlobalProtect with a passcode.
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
    version_vulnerable = False
    for major_version, min_version in non_vulnerable_versions.items():
        if major_version in system_info_output:
            current_version = system_info_output.split()[-1]
            if current_version < min_version:
                version_vulnerable = True
                break

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Extract the GlobalProtect configuration from the command output
    globalprotect_config = commands.show_globalprotect_config

    # Check if the configuration allows disabling GlobalProtect with a passcode
    allow_with_passcode = 'Allow User to Disable GlobalProtect App: Allow with Passcode' in globalprotect_config

    # Assert that the device is not vulnerable
    assert not allow_with_passcode, (
        f"Device {device.name} is vulnerable to CVE-2024-2431. "
        "The GlobalProtect app is configured to allow disabling with a passcode, which makes it susceptible to unauthorized disabling. "
        "For more information, see the Palo Alto Networks Security Advisory."
    )
