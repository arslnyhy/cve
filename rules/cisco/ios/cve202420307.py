from comfy import high

@high(
    name='rule_cve202420307',
    platform=['cisco_ios'],
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
        # 15.1(2) versions
        '15.1(2)SG8', '15.1(2)SY8', '15.1(2)SY9', '15.1(2)SY10', '15.1(2)SY11',
        '15.1(2)SY12', '15.1(2)SY13', '15.1(2)SY14', '15.1(2)SY15', '15.1(2)SY16',
        # 15.2(1) versions
        '15.2(1)SY3', '15.2(1)SY4', '15.2(1)SY5', '15.2(1)SY6', '15.2(1)SY7', '15.2(1)SY8',
        # 15.2(3/4/5) versions
        '15.2(3)E4', '15.2(3)E5',
        '15.2(4)M11', '15.2(4)E2', '15.2(4)E3', '15.2(4)E4', '15.2(4)E5', '15.2(4)E5a',
        '15.2(4)E6', '15.2(4)E7', '15.2(4)E8', '15.2(4)E9', '15.2(4)E10', '15.2(4)E10a',
        '15.2(4)E10d', '15.2(4)EC1', '15.2(4)EC2', '15.2(4)EA4', '15.2(4)EA5', '15.2(4)EA6',
        '15.2(4)EA7', '15.2(4)EA8', '15.2(4)EA9', '15.2(4)EA9a',
        '15.2(5)E', '15.2(5b)E', '15.2(5)EA',
        # 15.3 versions
        '15.3(3)S8', '15.3(3)S8a', '15.3(3)S9', '15.3(3)S10',
        '15.3(3)M8', '15.3(3)M8a', '15.3(3)M9', '15.3(3)M10',
        '15.3(1)SY1', '15.3(1)SY2', '15.3(3)JPI11',
        # 15.4 versions
        '15.4(1)SY', '15.4(1)SY1', '15.4(1)SY2', '15.4(1)SY3', '15.4(1)SY4',
        '15.4(3)S6', '15.4(3)S6a', '15.4(3)S7', '15.4(3)S8', '15.4(3)S9', '15.4(3)S10',
        # 15.5 versions
        '15.5(1)S4', '15.5(1)SY', '15.5(1)SY1', '15.5(1)SY2', '15.5(1)SY3', '15.5(1)SY4',
        '15.5(1)SY5', '15.5(1)SY6', '15.5(1)SY7', '15.5(1)SY8', '15.5(1)SY9', '15.5(1)SY10',
        '15.5(1)SY11',
        '15.5(2)S4', '15.5(2)T4',
        '15.5(3)S3', '15.5(3)S4', '15.5(3)S5', '15.5(3)S6', '15.5(3)S6a', '15.5(3)S6b',
        '15.5(3)S7', '15.5(3)S8', '15.5(3)S9', '15.5(3)S9a', '15.5(3)S10',
        '15.5(3)M3', '15.5(3)M4', '15.5(3)M4a', '15.5(3)M5', '15.5(3)M6', '15.5(3)M6a',
        '15.5(3)M7', '15.5(3)M8', '15.5(3)M9', '15.5(3)M10',
        # 15.7 versions
        '15.7(3)M', '15.7(3)M0a', '15.7(3)M1', '15.7(3)M2', '15.7(3)M3', '15.7(3)M4',
        '15.7(3)M4a', '15.7(3)M4b', '15.7(3)M5', '15.7(3)M6', '15.7(3)M7', '15.7(3)M8',
        '15.7(3)M9',
        # 15.8 versions
        '15.8(3)M', '15.8(3)M0a', '15.8(3)M0b', '15.8(3)M1', '15.8(3)M1a', '15.8(3)M2',
        '15.8(3)M2a', '15.8(3)M3', '15.8(3)M3a', '15.8(3)M3b', '15.8(3)M4', '15.8(3)M5',
        '15.8(3)M6', '15.8(3)M7', '15.8(3)M8', '15.8(3)M9', '15.8(3)M10',
        # 15.9 versions
        '15.9(3)M', '15.9(3)M0a', '15.9(3)M1', '15.9(3)M2', '15.9(3)M2a', '15.9(3)M3',
        '15.9(3)M3a', '15.9(3)M3b', '15.9(3)M4', '15.9(3)M4a', '15.9(3)M5', '15.9(3)M6',
        '15.9(3)M6a', '15.9(3)M6b', '15.9(3)M7', '15.9(3)M7a'
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
        f"The device is running a vulnerable version, IKEv1 fragmentation is enabled, and buffers huge size is set to {buffers_huge_size}. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz"
    )
