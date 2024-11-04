from comfy import high

@high(
    name='rule_cve202420318',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_platform='show platform',
        show_running_config='show running-config'
    ),
)
def rule_cve202420318(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20318 vulnerability in Cisco IOS XR devices.
    The vulnerability allows an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    by sending specific Ethernet frames to devices with affected Layer 2 transport configurations.
    The test verifies if the device is running a vulnerable version and has vulnerable hardware/configuration.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 6.5.x versions
        '6.5.2', '6.5.3',
        # 6.6.x versions
        '6.6.2', '6.6.3', '6.6.25',
        # 6.7.x versions
        '6.7.1', '6.7.2', '6.7.3',
        # 6.8.x versions
        '6.8.1', '6.8.2',
        # 6.9.x versions
        '6.9.1', '6.9.2',
        # 7.0.x versions
        '7.0.1', '7.0.2',
        # 7.1.x versions
        '7.1.1', '7.1.2', '7.1.3', '7.1.15',
        # 7.3.x versions
        '7.3.1', '7.3.2', '7.3.3', '7.3.5',
        # 7.4.x versions
        '7.4.1', '7.4.2',
        # 7.5.x versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4', '7.5.5',
        # 7.6.x versions
        '7.6.1', '7.6.2',
        # 7.7.x versions
        '7.7.1', '7.7.2',
        # 7.8.x versions
        '7.8.1', '7.8.2',
        # 7.9.x versions
        '7.9.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

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

    if not line_card_vulnerable:
        return

    # Extract the output of the 'show running-config' command to check Layer 2 transport configuration
    config_output = commands.show_running_config

    # Check for the presence of 'rewrite ingress tag pop' in the configuration
    rewrite_tag_present = 'rewrite ingress tag pop' in config_output

    # Check for 'load-balancing flow src-dst-ip' under l2vpn configuration
    load_balancing_present = 'load-balancing flow src-dst-ip' in config_output

    # Check for service policy or access-control filtering on Layer 2 interfaces
    service_policy_present = 'service-policy' in config_output or 'access-group' in config_output

    # Determine if the device is vulnerable based on configuration
    config_vulnerable = rewrite_tag_present and (load_balancing_present or service_policy_present)

    # Assert that the device is not vulnerable
    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20318. "
        "The device is running a vulnerable version, has vulnerable line cards installed, "
        "AND has a vulnerable Layer 2 transport configuration. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrl2vpn-jesrU3fc"
    )
