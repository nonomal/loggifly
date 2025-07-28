from systemd import journal
import argparse

"""
This script is for debugging purposes to read the last n lines of the systemd journal inside the container.
"""
def read_journal_lines(unit=None, lines=10, path="/var/log/journal/remote/"):
    j = journal.Reader(path=path)
    j.seek_tail()
    j.get_previous(lines)  

    if unit:
        j.add_match(_SYSTEMD_UNIT=unit)

    print(f"\n--- Last {lines} Lines {'of ' + unit if unit else 'all Journal Logs'} ---\n")
    for entry in j:
        ts = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S')
        msg = entry.get('MESSAGE', '')
        unit = entry.get('_SYSTEMD_UNIT', "")
        print(f"[{ts}] {unit} {msg}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read last n Journal-lines")
    parser.add_argument("-u", "--unit", help="Name of Systemd-Unit", default=None)
    parser.add_argument("-n", "--lines", help="Number of lines", type=int, default=10)
    parser.add_argument("-p", "--path", help="Path to journal files", default="/var/log/journal/remote/")
    args = parser.parse_args()

    read_journal_lines(unit=args.unit, lines=args.lines, path=args.path)
