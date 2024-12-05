from comfy import high

@high(
    name='rule_cve202430397',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_ike='show configuration | display set | match "security ike proposal.*authentication-method rsa-signatures"',
        show_pkid_status='show system processes extensive | match pkid'
    )
)
def rule_cve202430397(configuration, commands, device, devices):
    """
    This rule checks for CVE-2024-30397 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS)
    by sending invalid certificates that cause pkid to consume 100% CPU and become unresponsive.

    Args:
        configuration (str): The full device configuration
        commands (dict): Output of the executed commands
        device: The current device object
        devices: All devices in the test scope
    """
    # List of vulnerable software versions
    vulnerable_versions = [
        # Pre-20.4R3-S10 versions
        '20.4R3-S9', '20.4R3-S8', '20.4R3-S7', '20.4R3-S6', '20.4R3-S5',
        '20.4R3-S4', '20.4R3-S3', '20.4R3-S2', '20.4R3-S1', '20.4R3',
        # 21.2 versions before 21.2R3-S7
        '21.2R3-S6', '21.2R3-S5', '21.2R3-S4', '21.2R3-S3', '21.2R3-S2',
        '21.2R3-S1', '21.2R3', '21.2R2', '21.2R1',
        # 21.4 versions before 21.4R3-S5
        '21.4R3-S4', '21.4R3-S3', '21.4R3-S2', '21.4R3-S1',
        '21.4R3', '21.4R2', '21.4R1',
        # 22.1 versions before 22.1R3-S4
        '22.1R3-S3', '22.1R3-S2', '22.1R3-S1',
        '22.1R3', '22.1R2', '22.1R1',
        # 22.2 versions before 22.2R3-S3
        '22.2R3-S2', '22.2R3-S1', '22.2R3',
        '22.2R2', '22.2R1',
        # 22.3 versions before 22.3R3-S1
        '22.3R3', '22.3R2', '22.3R1',
        # 22.4 versions before 22.4R3
        '22.4R2', '22.4R1',
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if version is vulnerable
    version_output = commands.show_version
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    if not version_vulnerable:
        return

    # Check if IKE is configured with RSA signatures
    ike_config = commands.show_config_ike
    rsa_auth_enabled = 'authentication-method rsa-signatures' in ike_config

    if not rsa_auth_enabled:
        return

    # Check pkid CPU utilization
    pkid_output = commands.show_pkid_status
    high_cpu = False
    for line in pkid_output.splitlines():
        if 'pkid' in line:
            try:
                # Extract CPU percentage from the line
                cpu_pct = float(line.split()[-1].rstrip('%'))
                if cpu_pct > 90:  # Consider >90% as high CPU
                    high_cpu = True
                    break
            except (ValueError, IndexError):
                continue

    assert not high_cpu, (
        f"Device {device.name} is vulnerable to CVE-2024-30397. "
        "The device is running a vulnerable version with IKE RSA authentication configured "
        "and showing signs of pkid CPU exhaustion (>90%). This can prevent VPN negotiations "
        "from succeeding. "
        "Please upgrade to one of the following fixed versions: "
        "20.4R3-S10, 21.2R3-S7, 21.4R3-S5, 22.1R3-S4, 22.2R3-S3, 22.3R3-S1, "
        "22.4R3, 23.2R1-S2, 23.2R2, 23.4R1, or later. "
        "For more information, see https://supportportal.juniper.net/JSA79179"
    )
