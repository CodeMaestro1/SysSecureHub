import argparse

def main():
    parser = argparse.ArgumentParser(description="Process some files.")
    parser.add_argument('-d', '--directory_to_scan', required=True, help="Directory to scan")
    parser.add_argument('-s', '--signature_file', required=True, help="Signature file")
    parser.add_argument('-o', '--output_file', required=True, help="Output file")
    parser.add_argument('-r', '--real_time', action='store_true', help="Enable real-time option")

    args = parser.parse_args()

    print(f"Directory to scan: {args.directory_to_scan}")
    print(f"Signature file: {args.signature_file}")
    print(f"Output file: {args.output_file}")
    print(f"Real-time option: {args.real_time}")

if __name__ == '__main__':
    main()
