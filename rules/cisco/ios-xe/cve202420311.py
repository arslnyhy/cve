from comfy import high

@high(
    name='rule_cve202420311',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(check_lisp='show running-config | include router lisp'),
)
def rule_cve202420311(configuration, commands, device, devices):
    """
    This rule checks for the presence of the LISP feature in the device configuration.
    If LISP is enabled, the device is vulnerable to CVE-2024-20311, which can lead to a DoS condition.
    """

    # Extract the output of the command to check if LISP is configured
    lisp_config = commands.check_lisp

    # Check if the command output contains 'router lisp', indicating LISP is enabled
    # If LISP is enabled, the device is vulnerable to the CVE-2024-20311
    assert 'router lisp' not in lisp_config, (
        f"Device {device.name} is vulnerable to CVE-2024-20311. "
        "LISP is enabled, which could allow an attacker to cause a denial of service."
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP"
    )
