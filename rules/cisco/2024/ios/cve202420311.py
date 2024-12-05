from comfy import high


@high(
    name='rule_cve202420311',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_lisp='show running-config | include router lisp'
    ),
)
def rule_cve202420311(configuration, commands, device, devices):
    """
    This rule checks for the presence of the LISP feature in the device configuration.
    If LISP is enabled and the device is running a vulnerable version, the device is vulnerable 
    to CVE-2024-20311, which can lead to a DoS condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 15.1 versions
        '15.1(1)XB', '15.1(2)S', '15.1(2)S1', '15.1(2)S2', '15.1(3)S', '15.1(3)S0a',
        '15.1(3)S1', '15.1(3)S2', '15.1(3)S3', '15.1(3)S4', '15.1(3)S5', '15.1(3)S5a',
        '15.1(3)S6', '15.1(4)M', '15.1(4)M1', '15.1(4)M2', '15.1(4)M3', '15.1(4)M3a',
        '15.1(4)M4', '15.1(4)M5', '15.1(4)M6', '15.1(4)M7', '15.1(4)M8', '15.1(4)M9',
        '15.1(4)M10', '15.1(4)GC', '15.1(4)GC1', '15.1(4)GC2',
        # 15.2 versions
        '15.2(1)S', '15.2(1)S1', '15.2(1)S2', '15.2(2)S', '15.2(2)S0a', '15.2(2)S0c',
        '15.2(2)S1', '15.2(2)S2', '15.2(4)S', '15.2(4)S1', '15.2(4)S2', '15.2(4)S3',
        '15.2(4)S3a', '15.2(4)S4', '15.2(4)S4a', '15.2(4)S5', '15.2(4)S6', '15.2(4)S7',
        '15.2(4)M', '15.2(4)M1', '15.2(4)M2', '15.2(4)M3', '15.2(4)M4', '15.2(4)M5',
        '15.2(4)M6', '15.2(4)M6a', '15.2(4)M9', '15.2(4)M10', '15.2(4)M11',
        # 15.3 versions
        '15.3(1)T', '15.3(1)T1', '15.3(1)T2', '15.3(1)T3', '15.3(1)T4', '15.3(2)T',
        '15.3(2)T1', '15.3(2)T2', '15.3(2)T3', '15.3(2)T4', '15.3(3)M', '15.3(3)M1',
        '15.3(3)M2', '15.3(3)M3', '15.3(3)M4', '15.3(3)M6', '15.3(3)M7', '15.3(3)M8',
        '15.3(3)M8a', '15.3(3)M9', '15.3(3)M10',
        # 15.4 versions
        '15.4(1)T', '15.4(1)T1', '15.4(1)T2', '15.4(2)T', '15.4(2)T4',
        # 15.5 versions
        '15.5(1)T3', '15.5(1)T4', '15.5(2)T', '15.5(2)T1', '15.5(2)T2', '15.5(2)T3',
        '15.5(2)T4', '15.5(3)M', '15.5(3)M0a', '15.5(3)M1', '15.5(3)M2', '15.5(3)M3',
        '15.5(3)M4', '15.5(3)M4a', '15.5(3)M5', '15.5(3)M6', '15.5(3)M6a', '15.5(3)M7',
        '15.5(3)M8', '15.5(3)M9', '15.5(3)M10',
        # 15.6 versions
        '15.6(1)T', '15.6(1)T0a', '15.6(1)T1', '15.6(1)T2', '15.6(1)T3', '15.6(2)T',
        '15.6(2)T1', '15.6(2)T2', '15.6(2)T3', '15.6(3)M', '15.6(3)M0a', '15.6(3)M1',
        '15.6(3)M1b', '15.6(3)M2', '15.6(3)M2a', '15.6(3)M3', '15.6(3)M3a', '15.6(3)M4',
        '15.6(3)M5', '15.6(3)M6', '15.6(3)M6a', '15.6(3)M6b', '15.6(3)M7', '15.6(3)M8',
        '15.6(3)M9',
        # 15.7 versions
        '15.7(3)M', '15.7(3)M0a', '15.7(3)M1', '15.7(3)M2', '15.7(3)M3', '15.7(3)M4',
        '15.7(3)M4a', '15.7(3)M4b', '15.7(3)M5', '15.7(3)M6', '15.7(3)M7', '15.7(3)M8',
        '15.7(3)M9',
        # 15.8 versions
        '15.8(3)M', '15.8(3)M0a', '15.8(3)M0b', '15.8(3)M1', '15.8(3)M1a', '15.8(3)M2',
        '15.8(3)M2a', '15.8(3)M3', '15.8(3)M3a', '15.8(3)M3b', '15.8(3)M4', '15.8(3)M5',
        '15.8(3)M6', '15.8(3)M7', '15.8(3)M8', '15.8(3)M9', '15.8(3)M10',
        # 15.9 versions
        '15.9(3)M', '15.9(3)M0a', '15.9(3)M1', '15.9(3)M2', '15.9(3)M2a', '15.9(3)M3',
        '15.9(3)M3a', '15.9(3)M3b', '15.9(3)M4', '15.9(3)M4a', '15.9(3)M5', '15.9(3)M6',
        '15.9(3)M6a', '15.9(3)M6b', '15.9(3)M7', '15.9(3)M7a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check if LISP is configured
    lisp_config = commands.check_lisp

    # Check if the command output contains 'router lisp', indicating LISP is enabled
    lisp_enabled = 'router lisp' in lisp_config

    # If LISP is enabled and version is vulnerable, the device is vulnerable to CVE-2024-20311
    assert not lisp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2024-20311. "
        "The device is running a vulnerable version AND has LISP enabled, which could allow an attacker to cause a denial of service. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lisp-3gYXs3qP"
    )
