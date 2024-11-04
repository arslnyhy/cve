from comfy import high

@high(
    name='rule_cve202420327',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_platform='show platform',
        show_running_config_pppoe='show running-config pppoe bba-group',
        show_running_config_interface='show running-config interface | utility egrep "interface|pppoe enable bba-group|bundle id"'
    ),
)
def rule_cve202420327(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20327 vulnerability in Cisco ASR 9000 Series Routers.
    The vulnerability allows an unauthenticated, adjacent attacker to crash the ppp_ma process,
    resulting in a denial of service (DoS) condition due to improper handling of malformed PPPoE packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions from the notepad
    vulnerable_versions = [
        # 5.2.x versions
        '5.2.0', '5.2.2', '5.2.4',
        # 5.3.x versions
        '5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4',
        # 6.0.x versions
        '6.0.0', '6.0.1', '6.0.2',
        # 6.1.x versions
        '6.1.1', '6.1.2', '6.1.3', '6.1.4',
        # 6.2.x versions
        '6.2.1', '6.2.2', '6.2.3', '6.2.25',
        # 6.3.x versions
        '6.3.2', '6.3.3',
        # 6.4.x versions
        '6.4.1', '6.4.2',
        # 6.5.x versions
        '6.5.1', '6.5.2', '6.5.3',
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
        '7.9.1', '7.9.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the 'show platform' command
    platform_output = commands.show_platform

    # Define the list of vulnerable line cards
    vulnerable_line_cards = [
        'A9K-16X100GE-TR', 'A99-16X100GE-X-SE', 'A99-32X100GE-TR',
        'A9K-4HG-FLEX-TR', 'A9K-4HG-FLEX-SE', 'A99-4HG-FLEX-TR',
        'A99-4HG-FLEX-SE', 'A9K-8HG-FLEX-TR', 'A9K-8HG-FLEX-SE',
        'A9K-20HG-FLEX-TR', 'A9K-20HG-FLEX-SE', 'A99-32X100GE-X-TR',
        'A99-32X100GE-X-SE', 'A99-10X400GE-X-TR', 'A99-10X400GE-X-SE'
    ]

    # Check if any vulnerable line card is installed
    has_vulnerable_line_card = any(card in platform_output for card in vulnerable_line_cards)

    if not has_vulnerable_line_card:
        return

    # Extract the output of the 'show running-config pppoe bba-group' command
    pppoe_bba_group_output = commands.show_running_config_pppoe

    # Check if BNG PPPoE is enabled globally
    is_pppoe_enabled_globally = 'pppoe bba-group' in pppoe_bba_group_output

    # Extract the output of the 'show running-config interface' command
    interface_output = commands.show_running_config_interface

    # Check if PPPoE is enabled on any interface
    is_pppoe_enabled_on_interface = 'pppoe enable bba-group' in interface_output

    # Assert that the device is not vulnerable
    # The device is vulnerable if it has a vulnerable line card, PPPoE is enabled globally,
    # and PPPoE is enabled on at least one interface
    assert not (has_vulnerable_line_card and is_pppoe_enabled_globally and is_pppoe_enabled_on_interface), (
        f"Device {device.name} is vulnerable to CVE-2024-20327: "
        "The device is running a vulnerable version, has vulnerable line cards installed, "
        "AND has PPPoE enabled globally and on interfaces. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pppma-JKWFgneW"
    )
