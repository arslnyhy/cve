from comfy import high

@high(
    name='rule_cve20211227',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_nxapi='show running-config | include feature nxapi'
    ),
)
def rule_cve20211227(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1227 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient CSRF protections for the NX-API feature.
    An unauthenticated, remote attacker could exploit this vulnerability by persuading
    a user of the NX-API to follow a malicious link, allowing them to perform arbitrary
    actions with the privilege level of the affected user.
    Note: The NX-API feature is disabled by default.
    """
    # Extract the output of the command to check NX-API configuration
    nxapi_output = commands.check_nxapi

    # Check if NX-API is enabled
    nxapi_enabled = 'feature nxapi' in nxapi_output

    # If NX-API is not enabled, device is not vulnerable
    if not nxapi_enabled:
        return

    # Assert that the device is not vulnerable
    assert not nxapi_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1227. "
        "The device has NX-API enabled, which could allow an unauthenticated attacker "
        "to perform arbitrary actions through CSRF attacks. "
        "For more information, see https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nxapi-csrf-wRMzWL9z"
    )
