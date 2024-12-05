from comfy import high

@high(
    name='rule_cve202420456',
    platform=['cisco_xr'],
    commands=dict(show_version='show version'),
)
def rule_cve202420456(configuration, commands, device, devices):
    """
    This rule checks for the presence of a specific vulnerability (CVE-2024-20456) in Cisco IOS XR devices.
    The vulnerability allows an attacker with high privileges to bypass the secure boot process and load unverified software.
    This is due to an error in the software build process.
    """

    # Extract the output of the 'show version' command
    show_version_output = commands.show_version

    # Check if the device is running the vulnerable version 24.2.1
    is_vulnerable_version = '24.2.1' in show_version_output

    # Assert that the device is not running the vulnerable version
    assert not is_vulnerable_version, (
        f"Device {device.name} is running vulnerable version 24.2.1."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-secure-boot-quD5g8Ap"
    )
