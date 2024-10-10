@high(
    name='rule_cve202420318',
    platform=['cisco_xr'],
    commands=dict(
        show_platform='show platform',
        show_running_config='show running-config'
    ),
)
def rule_cve202420318(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20318 vulnerability in Cisco IOS XR devices.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    by sending specific Ethernet frames to devices with affected Layer 2 transport configurations.
    """

    # Extract the output of the 'show platform' command to determine installed line cards
    platform_output = commands.show_platform

    # List of vulnerable line cards (Lightspeed and Lightspeed-Plus based)
    vulnerable_line_cards = [
        'A9K-16X100GE-TR', 'A99-16X100GE-X-SE', 'A99-32X100GE-TR',
        'A9K-4HG-FLEX-SE', 'A9K-4HG-FLEX-TR', 'A9K-8HG-FLEX-SE',
        'A9K-8HG-FLEX-TR', 'A9K-20HG-FLEX-SE', 'A9K-20HG-FLEX-TR',
        'A99-4HG-FLEX-SE', 'A99-4HG-FLEX-TR', 'A99-10X400GE-X-SE',
        'A99-10X400GE-X-TR', 'A99-32X100GE-X-SE', 'A99-32X100GE-X-TR'
    ]

    # Check if any vulnerable line card is installed
    line_card_vulnerable = any(card in platform_output for card in vulnerable_line_cards)

    # Extract the output of the 'show running-config' command to check Layer 2 transport configuration
    config_output = commands.show_running_config

    # Check for the presence of 'rewrite ingress tag pop' in the configuration
    rewrite_tag_present = 'rewrite ingress tag pop' in config_output

    # Check for 'load-balancing flow src-dst-ip' under l2vpn configuration
    load_balancing_present = 'load-balancing flow src-dst-ip' in config_output

    # Check for service policy or access-control filtering on Layer 2 interfaces
    service_policy_present = 'service-policy' in config_output or 'access-group' in config_output

    # Determine if the device is vulnerable
    is_vulnerable = (
        line_card_vulnerable and
        rewrite_tag_present and
        (load_balancing_present or service_policy_present)
    )

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20318. "
        "Please apply the necessary software updates or configuration changes."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrl2vpn-jesrU3fc"
    )
