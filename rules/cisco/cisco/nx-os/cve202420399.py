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
    If the version is one of the known vulnerable versions, the test will fail.
    """

    # List of known vulnerable versions of NX-OS
    vulnerable_versions = [
        '7.3(0)N1(1)',  # Example version, replace with actual vulnerable versions
        '9.2(3)',       # Example version, replace with actual vulnerable versions
        # Add more versions as necessary
    ]

    # Extract the software version from the 'show version' command output
    show_version_output = commands.show_version
    # Example: Parse the version from the output (assuming a specific format)
    # This is a simplified example; actual parsing might require regex or more complex logic
    version_line = next((line for line in show_version_output.splitlines() if 'NXOS' in line), None)
    if version_line:
        # Extract the version number from the line
        # Example: "NXOS: version 9.2(3)"
        version = version_line.split('version')[-1].strip()

        # Check if the extracted version is in the list of vulnerable versions
        assert version not in vulnerable_versions, f"Device is running a vulnerable version: {version}"
        "Fore more information, see https://www.sygnia.co/threat-reports-and-advisories/china-nexus-threat-group-velvet-ant-exploits-cisco-0-day/"

    # If the version line is not found, the test should raise an error
    else:
        raise ValueError("Unable to determine NX-OS version from 'show version' output.")
    
