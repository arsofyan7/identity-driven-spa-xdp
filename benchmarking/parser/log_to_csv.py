import csv
import sys

def parse_log(log_file):
    print(f"Parsing log file: {log_file}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_log(sys.argv[1])
