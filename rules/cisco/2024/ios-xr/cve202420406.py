from comfy import high

@high(
    name='rule_cve202420406',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        flex_algo='show running-config router isis | include flex-algo',
        microloop='show running-config router isis | include microloop',
        ti_lfa='show running-config router isis | include ti-lfa'
    ),
)
def rule_cve202420406(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20406 vulnerability in Cisco IOS XR devices.
    The vulnerability is present if the device has IS-IS Segment Routing Flexible Algorithm
    enabled along with either Microloop Avoidance or TI-LFA.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 6.8.x versions
        '6.8.1', '6.8.2',
        # 6.9.x versions
        '6.9.1', '6.9.2',
        # 7.4.x versions
        '7.4.1', '7.4.2', '7.4.15', '7.4.16',
        # 7.5.x versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5', '7.5.12',
        # 7.6.x versions
        '7.6.1', '7.6.2', '7.6.3', '7.6.15',
        # 7.7.x versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8.x versions
        '7.8.1', '7.8.2', '7.8.22',
        # 7.9.x versions
        '7.9.1', '7.9.2', '7.9.21',
        # 7.10.x versions
        '7.10.1', '7.10.2',
        # 7.11.x versions
        '7.11.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if IS-IS Segment Routing Flexible Algorithm is enabled
    flex_algo_enabled = 'flex-algo' in commands.flex_algo
    
    # Check if IS-IS Segment Routing Microloop Avoidance is enabled
    microloop_enabled = 'microloop' in commands.microloop
    
    # Check if TI-LFA for Flexible Algorithm is enabled
    ti_lfa_enabled = 'ti-lfa' in commands.ti_lfa

    # If IS-IS Segment Routing Flexible Algorithm is enabled and either Microloop Avoidance
    # or TI-LFA is enabled, the device is vulnerable
    is_vulnerable = flex_algo_enabled and (microloop_enabled or ti_lfa_enabled)

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the assertion will fail, indicating a high severity issue
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20406. "
        "The device is running a vulnerable version AND has IS-IS Segment Routing Flexible Algorithm enabled "
        "along with either Microloop Avoidance or TI-LFA. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-isis-xehpbVNe"
    )
