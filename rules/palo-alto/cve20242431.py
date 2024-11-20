from comfy import high

@high(
    name='rule_cve20242431',
    platform=['paloalto_panos'],
    commands=dict(
        show_globalprotect_config='show globalprotect config'
    ),
)
def rule_cve20242431(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-2431 vulnerability in Palo Alto Networks GlobalProtect App.
    The vulnerability allows a non-privileged user to disable the GlobalProtect app without needing
    the passcode in configurations that allow a user to disable GlobalProtect with a passcode.
    """
    # Extract the GlobalProtect configuration from the command output
    globalprotect_config = commands.show_globalprotect_config

    # Check if the configuration allows disabling GlobalProtect with a passcode
    allow_with_passcode = 'Allow User to Disable GlobalProtect App: Allow with Passcode' in globalprotect_config

    # Assert that the device is not vulnerable
    # If the configuration allows disabling with a passcode, the test will fail, indicating the presence of the vulnerability
    assert not allow_with_passcode, (
        f"Device {device.name} is vulnerable to CVE-2024-2431. "
        "The GlobalProtect app is configured to allow disabling with a passcode, which makes it susceptible to unauthorized disabling. "
        "For more information, see the Palo Alto Networks Security Advisory."
    )
