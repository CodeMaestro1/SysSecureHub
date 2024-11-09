import argparse

from taskC_1 import real_time_monitor_tool
from taskB_1 import taskB_packaged

def main():
    parser = argparse.ArgumentParser(description="Process some files.", formatter_class=argparse.MetavarTypeHelpFormatter)
    parser.add_argument('-d', '--directory_to_scan', required=True, help="Directory to scan", type = str)
    parser.add_argument('-s', '--signature_file', required=True, help="Signature file", type = str)
    parser.add_argument('-o', '--output_file', required=True, help="Output file", type = str)
    parser.add_argument('-r', '--real_time', action='store_true', help="Enable real-time option")

    args = parser.parse_args()

    if args.real_time:
        real_time_monitor_tool(args.directory_to_scan, args.signature_file)
    else:
        print("Real-time option not enabled.")
        taskB_packaged(args.directory_to_scan, args.signature_file)


    #print(f"Directory to scan: {args.directory_to_scan}")
    #print(f"Signature file: {args.signature_file}")
    #print(f"Output file: {args.output_file}")
    #print(f"Real-time option: {args.real_time}")

if __name__ == '__main__':
    main()
