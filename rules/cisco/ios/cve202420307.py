from comfy import high


@high(
    name='rule_cve202420307',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(
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
        f"IKEv1 fragmentation is enabled and buffers huge size is set to {buffers_huge_size}. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ikev1-NO2ccFWz"
    )
