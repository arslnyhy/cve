from comfy import high

@high(
    name='rule_cve202420381',
    platform=['cisco_ios', 'cisco_nxos', 'cisco_xr'],
    commands=dict(show_confd_conf='show running-config | include confd.conf'),
)
def rule_cve202420381(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2024-20381 vulnerability, which affects devices
    with the JSON-RPC API feature enabled in ConfD. The vulnerability allows an
    authenticated, remote attacker to modify the configuration of an affected
    application or device due to improper authorization checks.

    The test inspects the 'confd.conf' configuration file to see if the 'webui'
    feature is enabled. If enabled, it indicates that the JSON-RPC API is active,
    making the device susceptible to this vulnerability.
    """

    # Fetch the output of the 'show running-config' command filtered for 'confd.conf'
    confd_conf_output = commands.show_confd_conf

    # Check if the 'webui' feature is enabled in the confd.conf configuration
    if '<webui>' in confd_conf_output and '<enabled>true</enabled>' in confd_conf_output:
        # If both the <webui> tag and <enabled>true</enabled> are present, the device is vulnerable
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2024-20381. "
            "The 'webui' feature is enabled in the confd.conf configuration, "
            "indicating that the JSON-RPC API is active."
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nso-auth-bypass-QnTEesp"
        )
    else:
        # If the 'webui' feature is not enabled, the device is not vulnerable
        assert True
