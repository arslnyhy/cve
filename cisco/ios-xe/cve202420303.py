@high(
    name='rule_cve202420303',
    platform=['cisco_ios'],
    commands=dict(
        show_ap_status='show ap status | i Flex',
        show_mdns_sd_summary='show mdns-sd summary'
    ),
)
def rule_cve202420303(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20303 vulnerability in Cisco IOS XE Software for Wireless LAN Controllers.
    The vulnerability is due to improper management of mDNS client entries, which can lead to a DoS condition.
    This test verifies if the mDNS gateway feature is enabled and if there are any APs in FlexConnect mode.
    If both conditions are met, the device is considered vulnerable.
    """

    # Check if there are any APs in FlexConnect mode
    ap_status_output = commands.show_ap_status
    ap_in_flexconnect_mode = 'FlexConnect' in ap_status_output

    # Check if the mDNS gateway feature is enabled
    mdns_summary_output = commands.show_mdns_sd_summary
    mdns_gateway_enabled = 'mDNS Gateway: Enabled' in mdns_summary_output

    # Assert that the device is not vulnerable
    # If both conditions are true, the device is vulnerable
    assert not (ap_in_flexconnect_mode and mdns_gateway_enabled), (
        "Device is vulnerable to CVE-2024-20303: mDNS gateway is enabled and APs are in FlexConnect mode."
    )
