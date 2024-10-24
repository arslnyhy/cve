from comfy import high

@high(
    name='rule_cve202420327',
    platform=['cisco_xr'],
    commands=dict(
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
        "Device is vulnerable to CVE-2024-20327: "
        "Vulnerable line card detected with PPPoE enabled."
        "Fore more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pppma-JKWFgneW"
    )
