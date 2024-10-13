@high(
    name='rule_cve202420271',
    platform=['cisco_wlc', 'cisco_xe'],  # Assuming the platforms are cisco_wlc and cisco_ios for Wireless LAN Controllers and APs
    commands=dict(show_version='show version'),  # Command to get the software version
)
def rule_cve202420271(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20271 vulnerability in Cisco Access Points.
    The vulnerability allows an unauthenticated, remote attacker to cause a denial of service (DoS) condition.
    It affects specific software versions of Cisco APs.
    """

    # Extract the software version from the command output
    version_output = commands.show_version
    # Example logic to extract version number, assuming version is in a specific line or format
    # This is a placeholder and should be adjusted based on actual output format
    software_version = None
    for line in version_output.splitlines():
        if "Software Version" in line:
            software_version = line.split()[-1]  # Adjust this index based on actual output format
            break

    # List of vulnerable software versions
    vulnerable_versions = [
        '8.9', '8.10', '17.2', '17.4', '17.5', '17.7', '17.8', '17.10', '17.11', '10.8.1', '10.5.2'
    ]

    # Check if the software version is in the list of vulnerable versions
    assert software_version not in vulnerable_versions, (
        f"Device {device.name} is running a vulnerable software version: {software_version}. "
        "Please upgrade to a fixed release to mitigate CVE-2024-20271."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-dos-h9TGGX6W"
    )
