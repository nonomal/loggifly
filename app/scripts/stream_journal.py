from systemd import journal
import argparse
import time
import select
import logging
"""
This script streams systemd journal logs inside the container.
"""


def stream_journal(unit=None, interval=None, path="/var/log/journal/remote/"):
    print(f"Starting to stream systemd journal logs for unit: {unit} with interval: {interval} seconds from path: {path}")
    j = journal.Reader(path=str(path))
    
    j.data_threshold = 64 * 1024 * 1024
    j.seek_tail()
    print(f"\n--- Streaming Journal Logs {'for ' + unit if unit else 'for all units'} ---\n")
    try:
        while True:
            wait_result = j.wait(timeout=1)
            if wait_result in  [journal.NOP, journal.INVALIDATE]:
                continue  # Blockiert bis neue Einträge kommen
            process_result = j.process()  # Verarbeitet neue Einträge
            print(f"Process result: {process_result}")
            for entry in j:
                ts = entry['__REALTIME_TIMESTAMP'].strftime('%Y-%m-%d %H:%M:%S')
                msg = entry.get('MESSAGE', '')
                unit = entry.get('_SYSTEMD_UNIT', "")
                print(f"[{ts}] {unit} {msg}")
                print()

    except KeyboardInterrupt:
        print("\nStopped log streaming.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream systemd journal logs.")
    parser.add_argument("-u", "--unit", help="Name of Systemd-Unit", default=None)
    parser.add_argument("-i", "--interval", help="Polling interval in seconds", type=float, default=1.0)
    parser.add_argument("-p", "--path", help="Path to journal files", default="/var/log/journal/remote/")
    args = parser.parse_args()

    stream_journal(unit=args.unit, interval=args.interval, path=args.path)