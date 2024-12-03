from comfy import high

@high(
    name='rule_cve202442503',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_lua_config='show configuration | include lua'
    ),
)
def rule_cve202442503(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42503 vulnerability in ArubaOS devices.
    The vulnerability allows authenticated attackers to execute arbitrary commands through
    the Lua package in the command line interface (CLI), which could lead to complete
    system compromise through command injection.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions based on CVE data
    vulnerable_versions = [
        # 10.6.x versions
        '10.6.0.2', '10.6.0.1', '10.6.0.0',
        # 10.5.x and below
        '10.5.0.0', '10.4.0.0', '10.3.0.0',
        # 8.12.x versions
        '8.12.0.1', '8.12.0.0',
        # 8.11.x versions
        '8.11.0.0',
        # 8.10.x versions
        '8.10.0.13', '8.10.0.12', '8.10.0.11', '8.10.0.10',
        '8.10.0.9', '8.10.0.8', '8.10.0.7', '8.10.0.6',
        '8.10.0.5', '8.10.0.4', '8.10.0.3', '8.10.0.2',
        '8.10.0.1', '8.10.0.0',
        # 8.9.x and below
        '8.9.0.0', '6.5.4.0'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Lua package is enabled
    lua_config = commands.show_lua_config
    lua_enabled = 'lua enable' in lua_config

    # Assert that the device is not vulnerable
    assert not lua_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42503. "
        "The device is running a vulnerable version with Lua package enabled, "
        "which makes it susceptible to authenticated command injection attacks "
        "that could lead to arbitrary command execution as a privileged user."
    )
