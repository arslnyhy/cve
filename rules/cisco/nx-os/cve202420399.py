from comfy import medium

@medium(
    name='rule_cve_202420399',
    platform=['cisco_nxos'],
    commands=dict(show_version='show version'),
)
def rule_cve202420399(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2024-20399, a command injection vulnerability
    in Cisco NX-OS Software CLI. The vulnerability allows attackers with valid admin credentials
    to escape the NX-OS CLI and execute arbitrary commands on the underlying Linux OS.

    The rule checks the device's software version to determine if it is vulnerable.
    If the version is one of the known vulnerable plat, the test will fail.
    """

    # List of known vulnerable platforms of NX-OS
    vulnerable_platforms = [
        'MDS9000',
        'Nexus3000',
        'Nexus5500',
        'Nexus5600',
        'Nexus6000',
        'Nexus7000',
        'Nexus9000',
    ]

    # Extract the software version from the 'show version' command output
    show_version_output = commands.show_version
    for platform in vulnerable_platforms:
        if platform in show_version_output:
            assert False, f"Device is running a vulnerable platform: {platform}"
            "Fore more information, see https://www.sygnia.co/threat-reports-and-advisories/china-nexus-threat-group-velvet-ant-exploits-cisco-0-day/"
