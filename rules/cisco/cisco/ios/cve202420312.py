@high(
    name='rule_cve202420312',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(show_running_config='show running-config | section router isis'),
)
def rule_cve202420312(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20312 vulnerability in Cisco IOS and IOS XE devices.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    condition on an affected device by sending a crafted IS-IS packet.

    The test checks if the device is configured for IS-IS routing and if it is operating as a Level 1
    or Level 1-2 router, which makes it vulnerable to this issue.
    """

    # Extract the output of the 'show running-config | section router isis' command
    isis_config = commands.show_running_config

    # Check if the device is configured for IS-IS routing
    if 'router isis' in isis_config:
        # Check if the device is operating as a Level 1 or Level 1-2 router
        if 'is-type level-1' in isis_config or 'is-type level-1-2' in isis_config:
            # If the device is configured as a Level 1 or Level 1-2 router, it is vulnerable
            assert False, (
                f"Device {device.name} is vulnerable to CVE-2024-20312. "
                "It is configured for IS-IS routing and operating as a Level 1 or Level 1-2 router."
            )
        else:
            # If the device is operating as a Level 2-only router, it is not vulnerable
            assert True, (
                f"Device {device.name} is not vulnerable to CVE-2024-20312. "
                "It is configured for IS-IS routing but operating as a Level 2-only router."
            )
    else:
        # If the device is not configured for IS-IS routing, it is not vulnerable
        assert True, (
            f"Device {device.name} is not vulnerable to CVE-2024-20312. "
            "It is not configured for IS-IS routing."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-isis-sGjyOUHX"
        )
