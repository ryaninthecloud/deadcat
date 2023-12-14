'''
Witness is the traffic capturing conduit for
passing traffic to the correct services to capture
and analyse the information
'''
import configparser as cps
import scapy

def validate_configuration_file(filepath: str) -> dict:
    '''
    Reads and validates the configuration file
    
    Arguments:
    -filepath: string -- the location of the ini file

    Returns: 
    -dictionary: keys=[capture_interface, exlcuded_ips]
    '''
    parser = cps.ConfigParser()
    configuration_dictionary = {}

    try:
        parser.read(filepath)
    except FileNotFoundError:
        raise SystemExit(f"Cannot find configuration file at {filepath}")
    except PermissionError:
        raise SystemExit(f"Permission denied when accessing {filepath}")

    if not parser['DEADCAT_DEFAULT']:
        raise SystemExit(f"{filepath} missing [DEFAULT_DEADCAT] section.")

    default_configurations = parser['DEADCAT_DEFAULT']

    if not default_configurations['capture_interface']:
        raise SystemExit(f"{filepath} missing capture_interface in 'DEADCAT_DEFAULT'")

    capture_interface = default_configurations['capture_interface']

    if not default_configurations['excluded_ips']:
        raise SystemExit(f"{filepath} missing excluded_ips in 'DEADCAT_DEFAULT'")

    excluded_ips = default_configurations['excluded_ips'].strip("[]").split(',')

    return {
        'capture_interface':capture_interface,
        'exlcuded_ips':excluded_ips
    }