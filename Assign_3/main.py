import argparse
import logging.config
import configparser
import os

from taskC_1 import real_time_monitor_tool
from taskB_1 import taskB_packaged

def update_log_file(logging_file_name):
    config = configparser.ConfigParser()
    try:
        config.read('mylogger.conf')
        
        current_log_file = config.get('handler_file', 'args', fallback=None)
        new_log_file = f"('{logging_file_name}.log', 'a')"
        
        if current_log_file != new_log_file:
            config.set('handler_file', 'args', new_log_file)
            with open('mylogger.conf', 'w') as configfile:
                config.write(configfile)
    except (configparser.Error, IOError, OSError) as e:
        print(f"Error updating log file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Process some files.", formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('-d', '--directory_to_scan', required=True, help="Directory to scan", type=str)
    parser.add_argument('-s', '--signature_file', required=True, help="Signature file", type=str)
    parser.add_argument('-o', '--output_file', required=True, help="Output file", type=str)
    parser.add_argument('-r', '--real_time', action='store_true', help="Enable real-time option")

    args = parser.parse_args()

    update_log_file(args.output_file)
    logging.config.fileConfig(fname='mylogger.conf', disable_existing_loggers=False)

    directory_to_scan = os.path.abspath(args.directory_to_scan)
    signature_file = os.path.abspath(args.signature_file)

    if args.real_time:
        real_time_monitor_tool(directory_to_scan, signature_file)
    else:
        taskB_packaged(directory_to_scan, signature_file)


if __name__ == '__main__':
    main()
