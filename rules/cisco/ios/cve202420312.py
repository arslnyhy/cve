from comfy import high


@high(
    name='rule_cve202420312',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | section router isis'
    ),
)
def rule_cve202420312(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20312 vulnerability in Cisco IOS and IOS XE devices.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    condition on an affected device by sending a crafted IS-IS packet.

    The test checks if the device is running a vulnerable version and if it is configured for IS-IS routing 
    and operating as a Level 1 or Level 1-2 router, which makes it vulnerable to this issue.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 15.1(2) versions
        '15.1(2)SG', '15.1(2)SG1', '15.1(2)SG2', '15.1(2)SG3', '15.1(2)SG4',
        '15.1(2)SG5', '15.1(2)SG6', '15.1(2)SG7', '15.1(2)SG8',
        # 15.2 versions
        '15.2(1)S', '15.2(1)S1', '15.2(1)S2', '15.2(2)S', '15.2(2)S0a', '15.2(2)S0c',
        '15.2(2)S1', '15.2(2)S2', '15.2(4)S', '15.2(4)S1', '15.2(4)S2', '15.2(4)S3',
        '15.2(4)S3a', '15.2(4)S4', '15.2(4)S4a', '15.2(4)S5', '15.2(4)S6', '15.2(4)S7',
        # 15.3 versions
        '15.3(1)S', '15.3(1)S1', '15.3(1)S2', '15.3(2)S', '15.3(2)S1', '15.3(2)S2',
        '15.3(3)S', '15.3(3)S1', '15.3(3)S1a', '15.3(3)S2', '15.3(3)S3', '15.3(3)S4',
        '15.3(3)S5', '15.3(3)S6', '15.3(3)S7', '15.3(3)S8', '15.3(3)S8a', '15.3(3)S9',
        '15.3(3)S10',
        # 15.4 versions
        '15.4(1)S', '15.4(1)S1', '15.4(1)S2', '15.4(1)S3', '15.4(1)S4',
        '15.4(2)S', '15.4(2)S1', '15.4(2)S2', '15.4(2)S3', '15.4(2)S4',
        '15.4(3)S', '15.4(3)S1', '15.4(3)S2', '15.4(3)S3', '15.4(3)S4', '15.4(3)S5',
        '15.4(3)S6', '15.4(3)S6a', '15.4(3)S7', '15.4(3)S8', '15.4(3)S9', '15.4(3)S10',
        # 15.5 versions
        '15.5(1)S', '15.5(1)S1', '15.5(1)S2', '15.5(1)S3', '15.5(1)S4',
        '15.5(2)S', '15.5(2)S1', '15.5(2)S2', '15.5(2)S3', '15.5(2)S4',
        '15.5(3)S', '15.5(3)S0a', '15.5(3)S1', '15.5(3)S1a', '15.5(3)S2', '15.5(3)S3',
        '15.5(3)S4', '15.5(3)S5', '15.5(3)S6', '15.5(3)S6a', '15.5(3)S6b', '15.5(3)S7',
        '15.5(3)S8', '15.5(3)S9', '15.5(3)S9a', '15.5(3)S10',
        # 15.6 versions
        '15.6(1)S', '15.6(1)S1', '15.6(1)S2', '15.6(1)S3', '15.6(1)S4',
        '15.6(2)S', '15.6(2)S1', '15.6(2)S2', '15.6(2)S3', '15.6(2)S4'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the 'show running-config | section router isis' command
    isis_config = commands.show_running_config

    # Check if the device is configured for IS-IS routing
    if 'router isis' in isis_config:
        # Check if the device is operating as a Level 1 or Level 1-2 router
        if 'is-type level-1' in isis_config or 'is-type level-1-2' in isis_config:
            # If the device is configured as a Level 1 or Level 1-2 router, it is vulnerable
            assert False, (
                f"Device {device.name} is vulnerable to CVE-2024-20312. "
                "The device is running a vulnerable version AND is configured for IS-IS routing "
                "operating as a Level 1 or Level 1-2 router. "
                "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-isis-sGjyOUHX"
            )
        else:
            # If the device is operating as a Level 2-only router, it is not vulnerable
            assert True, (
                f"Device {device.name} is not vulnerable to CVE-2024-20312. "
                "Although running a vulnerable version, it is configured for IS-IS routing "
                "but operating as a Level 2-only router."
            )
    else:
        # If the device is not configured for IS-IS routing, it is not vulnerable
        assert True, (
            f"Device {device.name} is not vulnerable to CVE-2024-20312. "
            "Although running a vulnerable version, it is not configured for IS-IS routing."
        )
