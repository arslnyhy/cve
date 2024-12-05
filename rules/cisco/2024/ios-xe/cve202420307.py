from comfy import high

@high(
    name='rule_cve202420307',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        show_ikev1_fragmentation='show running-config | include crypto isakmp fragmentation',
        show_buffers_huge='show running-config | include buffers huge'
    ),
)
def rule_cve202420307(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20307 and CVE-2024-20308 vulnerability in Cisco IOS and IOS XE devices.
    The vulnerability is related to IKEv1 fragmentation, which can cause a heap overflow
    if exploited. The test checks if IKEv1 fragmentation is enabled and if the buffers huge
    size is set to a value greater than 32,767, which are the conditions for the vulnerability.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 3.x versions
        '3.4.8SG', '3.7.4E', '3.7.5E', '3.8.2E', '3.8.3E', '3.8.4E', '3.8.5E', '3.8.5aE',
        '3.8.6E', '3.8.7E', '3.8.8E', '3.8.9E', '3.8.10E', '3.9.0E',
        '3.10.8S', '3.10.8aS', '3.10.9S', '3.10.10S',
        '3.13.6S', '3.13.7S', '3.13.6aS', '3.13.7aS', '3.13.8S', '3.13.9S', '3.13.10S',
        '3.14.4S', '3.15.4S',
        '3.16.3S', '3.16.3aS', '3.16.4S', '3.16.4aS', '3.16.4bS', '3.16.5S', '3.16.4dS',
        '3.16.6S', '3.16.7S', '3.16.6bS', '3.16.7aS', '3.16.7bS', '3.16.8S', '3.16.9S',
        '3.16.10S',
        # 16.x versions
        '16.1.3', '16.2.1', '16.2.2',
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6',
        '16.3.7', '16.3.8', '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6',
        '16.6.7', '16.6.8', '16.6.9', '16.6.10',
        '16.7.1', '16.7.1a', '16.7.1b', '16.7.2', '16.7.3', '16.7.4',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.1d', '16.8.2',
        '16.8.1e', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4',
        '16.9.3a', '16.9.5', '16.9.5f', '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1c', '16.10.1e', '16.10.1d',
        '16.10.2', '16.10.1f', '16.10.1g', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.1w', '16.12.2', '16.12.1y',
        '16.12.2a', '16.12.3', '16.12.8', '16.12.2s', '16.12.1x', '16.12.1t', '16.12.4',
        '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.1z1', '16.12.5a',
        '16.12.5b', '16.12.1z2', '16.12.6a', '16.12.7', '16.12.9',
        # 17.x versions
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.1w', '17.3.2a', '17.3.1x',
        '17.3.1z', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b', '17.3.4c',
        '17.3.5a', '17.3.5b', '17.3.7',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1w', '17.6.1a', '17.6.1x', '17.6.3', '17.6.1y',
        '17.6.1z', '17.6.3a', '17.6.4', '17.6.1z1', '17.6.5', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.1w', '17.9.2', '17.9.1a', '17.9.1x', '17.9.1y', '17.9.3',
        '17.9.2a', '17.9.1x1', '17.9.3a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if IKEv1 fragmentation is enabled by looking for the specific configuration command
    show_ikev1_fragmentation = commands.show_ikev1_fragmentation
    ikev1_fragmentation_enabled = 'crypto isakmp fragmentation' in show_ikev1_fragmentation

    # Check if the buffers huge size is configured and greater than 32,767
    buffers_huge_output = commands.show_buffers_huge
    buffers_huge_size = None

    # If the buffers huge command is present, extract the size value
    if 'buffers huge size' in buffers_huge_output:
        try:
            # Extract the size value from the command output
            buffers_huge_size = int(buffers_huge_output[0].split()[-1])
        except (ValueError, AttributeError, IndexError):
            # If conversion fails, log a warning (not expected in correct output)
            print(f"Warning: Unable to parse buffers huge size on device {device.name}")

    # Determine if the device is vulnerable based on the conditions
    is_vulnerable = ikev1_fragmentation_enabled and (buffers_huge_size is not None and buffers_huge_size > 32767)

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20307 and CVE-2024-20308. "
        "The device is running a vulnerable version AND has IKEv1 fragmentation enabled with buffers huge size > 32,767. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz"
    )
