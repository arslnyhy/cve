from comfy import high

@high(
    name='rule_cve202420311',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_lisp='show running-config | include router lisp'
    ),
)
def rule_cve202420311(configuration, commands, device, devices):
    """
    This rule checks for the presence of the LISP feature in the device configuration.
    If LISP is enabled and the device is running a vulnerable version, the device is vulnerable 
    to CVE-2024-20311, which can lead to a DoS condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        '3.7.0S', '3.7.1S', '3.7.2S', '3.7.3S', '3.7.4S', '3.7.5S', '3.7.6S', '3.7.7S',
        '3.7.4aS', '3.7.2tS', '3.7.0bS', '3.7.1aS',
        '3.8.0S', '3.8.1S', '3.8.2S',
        '3.9.0S', '3.9.1S', '3.9.2S', '3.9.1aS', '3.9.0aS', '3.9.1E', '3.9.2E',
        '3.10.0S', '3.10.1S', '3.10.2S', '3.10.3S', '3.10.4S', '3.10.5S', '3.10.6S',
        '3.10.2tS', '3.10.7S', '3.10.1xbS', '3.10.8S', '3.10.8aS', '3.10.9S', '3.10.10S',
        '3.10.0E', '3.10.1E', '3.10.0cE', '3.10.2E', '3.10.3E',
        '3.11.0S', '3.11.1S', '3.11.2S', '3.11.3S', '3.11.4S',
        '3.11.0E', '3.11.1E', '3.11.2E', '3.11.3E', '3.11.1aE', '3.11.4E', '3.11.3aE',
        '3.11.5E', '3.11.6E', '3.11.7E', '3.11.8E',
        '3.12.0S', '3.12.1S', '3.12.2S', '3.12.3S', '3.12.0aS', '3.12.4S',
        '3.13.0S', '3.13.1S', '3.13.2S', '3.13.3S', '3.13.4S', '3.13.5S',
        '3.13.2aS', '3.13.0aS', '3.13.5aS', '3.13.6S', '3.13.7S', '3.13.6aS', '3.13.7aS',
        '3.13.8S', '3.13.9S', '3.13.10S',
        '3.14.0S', '3.14.1S', '3.14.2S', '3.14.3S', '3.14.4S',
        '3.15.0S', '3.15.1S', '3.15.2S', '3.15.1cS', '3.15.3S', '3.15.4S',
        '3.16.0S', '3.16.1S', '3.16.1aS', '3.16.2S', '3.16.2aS', '3.16.0cS', '3.16.3S',
        '3.16.2bS', '3.16.3aS', '3.16.4S', '3.16.4aS', '3.16.4bS', '3.16.5S', '3.16.4dS',
        '3.16.6S', '3.16.7S', '3.16.6bS', '3.16.7aS', '3.16.7bS', '3.16.8S', '3.16.9S',
        '3.16.10S',
        '3.17.0S', '3.17.1S', '3.17.2S', '3.17.1aS', '3.17.3S', '3.17.4S',
        '3.18.0aS', '3.18.0S', '3.18.1S', '3.18.2S', '3.18.3S', '3.18.4S',
        '3.18.0SP', '3.18.1SP', '3.18.1aSP', '3.18.1bSP', '3.18.1cSP', '3.18.2SP',
        '3.18.2aSP', '3.18.3SP', '3.18.4SP', '3.18.3aSP', '3.18.3bSP', '3.18.5SP',
        '3.18.6SP', '3.18.7SP', '3.18.8aSP', '3.18.9SP',
        '16.1.1', '16.1.2', '16.1.3',
        '16.2.1', '16.2.2',
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b',
        '16.3.6', '16.3.7', '16.3.8', '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a',
        '16.6.6', '16.6.7', '16.6.8', '16.6.9', '16.6.10',
        '16.7.1', '16.7.1a', '16.7.1b', '16.7.2', '16.7.3', '16.7.4',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.1d', '16.8.2',
        '16.8.1e', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4',
        '16.9.3a', '16.9.5', '16.9.5f', '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1c', '16.10.1e',
        '16.10.1d', '16.10.2', '16.10.1f', '16.10.1g', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.1w', '16.12.2',
        '16.12.1y', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s', '16.12.1x',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5',
        '16.12.6', '16.12.1z1', '16.12.5a', '16.12.5b', '16.12.1z2', '16.12.6a',
        '16.12.7', '16.12.9',
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

    # Extract the output of the command to check if LISP is configured
    lisp_config = commands.check_lisp

    # Check if the command output contains 'router lisp', indicating LISP is enabled
    lisp_enabled = 'router lisp' in lisp_config

    # Assert that LISP is not enabled to pass the test
    # If LISP is enabled and version is vulnerable, the device is vulnerable to CVE-2024-20311
    assert not lisp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-20311. "
        "The device is running a vulnerable version AND has LISP enabled, which could allow an attacker to cause a denial of service. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP"
    )
