from comfy import medium

@medium(
    name='rule_cve202420411',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_feature='show feature | include bash',
        show_running_config='show running-config | include shelltype'
    ),
)
def rule_cve202420411(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20411 vulnerability in Cisco NX-OS Software.
    The vulnerability allows an authenticated, local attacker with privileges to access
    the Bash shell to execute arbitrary code as root on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions from the notepad
    vulnerable_versions = [
        # 6.0(2) versions
        '6.0(2)A6(1)', '6.0(2)A6(1a)', '6.0(2)A6(2)', '6.0(2)A6(2a)', '6.0(2)A6(3)',
        '6.0(2)A6(3a)', '6.0(2)A6(4)', '6.0(2)A6(4a)', '6.0(2)A6(5)', '6.0(2)A6(5a)',
        '6.0(2)A6(5b)', '6.0(2)A6(6)', '6.0(2)A6(7)', '6.0(2)A6(8)', '6.0(2)A8(1)',
        '6.0(2)A8(2)', '6.0(2)A8(3)', '6.0(2)A8(4)', '6.0(2)A8(4a)', '6.0(2)A8(5)',
        '6.0(2)A8(6)', '6.0(2)A8(7)', '6.0(2)A8(7a)', '6.0(2)A8(7b)', '6.0(2)A8(8)',
        '6.0(2)A8(9)', '6.0(2)A8(10)', '6.0(2)A8(10a)', '6.0(2)A8(11)', '6.0(2)A8(11a)',
        '6.0(2)A8(11b)', '6.0(2)U6(1)', '6.0(2)U6(1a)', '6.0(2)U6(2)', '6.0(2)U6(2a)',
        '6.0(2)U6(3)', '6.0(2)U6(3a)', '6.0(2)U6(4)', '6.0(2)U6(4a)', '6.0(2)U6(5)',
        '6.0(2)U6(5a)', '6.0(2)U6(5b)', '6.0(2)U6(5c)', '6.0(2)U6(6)', '6.0(2)U6(7)',
        '6.0(2)U6(8)', '6.0(2)U6(9)', '6.0(2)U6(10)', '6.0(2)U6(10a)',

        # 7.0(3) versions
        '7.0(3)F1(1)', '7.0(3)F2(1)', '7.0(3)F2(2)', '7.0(3)F3(1)', '7.0(3)F3(2)',
        '7.0(3)F3(3)', '7.0(3)F3(3a)', '7.0(3)F3(3c)', '7.0(3)F3(4)', '7.0(3)F3(5)',
        '7.0(3)I4(1)', '7.0(3)I4(1t)', '7.0(3)I4(2)', '7.0(3)I4(3)', '7.0(3)I4(4)',
        '7.0(3)I4(5)', '7.0(3)I4(6)', '7.0(3)I4(6t)', '7.0(3)I4(7)', '7.0(3)I4(8)',
        '7.0(3)I4(8a)', '7.0(3)I4(8b)', '7.0(3)I4(8z)', '7.0(3)I4(9)', '7.0(3)I5(1)',
        '7.0(3)I5(2)', '7.0(3)I5(3)', '7.0(3)I5(3a)', '7.0(3)I5(3b)', '7.0(3)I6(1)',
        '7.0(3)I6(2)', '7.0(3)I7(1)', '7.0(3)I7(2)', '7.0(3)I7(3)', '7.0(3)I7(3z)',
        '7.0(3)I7(4)', '7.0(3)I7(5)', '7.0(3)I7(5a)', '7.0(3)I7(6)', '7.0(3)I7(6z)',
        '7.0(3)I7(7)', '7.0(3)I7(8)', '7.0(3)I7(9)', '7.0(3)I7(9w)', '7.0(3)I7(10)',
        '7.0(3)IC4(4)', '7.0(3)IM3(1)', '7.0(3)IM3(2)', '7.0(3)IM3(2a)', '7.0(3)IM3(2b)',
        '7.0(3)IM3(3)', '7.0(3)IM7(2)', '7.0(3)IA7(1)', '7.0(3)IA7(2)',

        # 9.2 versions
        '9.2(1)', '9.2(2)', '9.2(2t)', '9.2(2v)', '9.2(3)', '9.2(3y)', '9.2(4)',

        # 9.3 versions
        '9.3(1)', '9.3(1z)', '9.3(2)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(5w)', '9.3(6)',
        '9.3(7)', '9.3(7a)', '9.3(7k)', '9.3(8)', '9.3(9)', '9.3(10)', '9.3(11)', '9.3(12)',
        '9.3(13)',

        # 10.1 versions
        '10.1(1)', '10.1(2)', '10.1(2t)',

        # 10.2 versions
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(2a)', '10.2(3)', '10.2(3t)', '10.2(3v)',
        '10.2(4)', '10.2(5)', '10.2(6)', '10.2(7)',

        # 10.3 versions
        '10.3(1)', '10.3(2)', '10.3(3)', '10.3(3o)', '10.3(3p)', '10.3(3q)', '10.3(3r)',
        '10.3(3w)', '10.3(3x)', '10.3(4)', '10.3(4a)', '10.3(4g)', '10.3(99w)', '10.3(99x)',

        # 10.4 versions
        '10.4(1)', '10.4(2)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if the Bash shell feature is enabled
    bash_feature_output = commands.show_feature
    is_bash_enabled = 'enabled' in bash_feature_output

    # Check if any users are configured to use the Bash shell at login
    bash_shelltype_output = commands.show_running_config
    is_bash_shelltype_configured = 'shelltype bash' in bash_shelltype_output

    # Assert that neither the Bash shell is enabled nor any users are configured to use it
    # If either condition is true, the device is vulnerable to CVE-2024-20411
    assert not (is_bash_enabled or is_bash_shelltype_configured), (
        f"Device {device.name} is vulnerable to CVE-2024-20411. "
        "The device is running a vulnerable version AND has Bash shell enabled or users configured to use Bash shell at login. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bshacepe-bApeHSx7"
    )
