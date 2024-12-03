from comfy import high

@high(
    name='rule_cve202442500',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_nfs_config='show configuration | include nfs'
    ),
)
def rule_cve202442500(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-42500 vulnerability in HPE HP-UX ONCplus systems.
    The vulnerability allows unauthenticated remote attackers to cause denial of service (DoS)
    through the Network File System (NFSv4) services, which could lead to service interruption
    and system unavailability.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions based on CVE data
    # All versions less than B.11.31.24 are vulnerable
    vulnerable_versions = [
        'B.11.31.23', 'B.11.31.22', 'B.11.31.21', 'B.11.31.20',
        'B.11.31.19', 'B.11.31.18', 'B.11.31.17', 'B.11.31.16',
        'B.11.31.15', 'B.11.31.14', 'B.11.31.13', 'B.11.31.12',
        'B.11.31.11', 'B.11.31.10', 'B.11.31.09', 'B.11.31.08',
        'B.11.31.07', 'B.11.31.06', 'B.11.31.05', 'B.11.31.04',
        'B.11.31.03', 'B.11.31.02', 'B.11.31.01', 'B.11.31.00'
    ]

    # Check if the current version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if NFSv4 service is enabled
    nfs_config = commands.show_nfs_config
    nfsv4_enabled = 'nfs-server enable' in nfs_config

    # Assert that the device is not vulnerable
    assert not nfsv4_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-42500. "
        "The device is running a vulnerable version with NFSv4 services enabled, "
        "which makes it susceptible to unauthenticated DoS attacks "
        "that could lead to service interruption and system unavailability."
    )
