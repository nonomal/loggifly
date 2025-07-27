from systemd import journal
import logging
import time
import threading
import subprocess
import os
from datetime import datetime
import select

from line_processor import LogProcessor
from load_config import GlobalConfig
from notifier import send_notification



class SystemdMonitor():
    """Monitor systemd journal entries for specific services."""
    
    def __init__(self, config: GlobalConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.shutdown_event = threading.Event()       
        self.reader_stopped_event = threading.Event()
        self.reader_stop_event = threading.Event()
        self.path = os.environ.get("JOURNAL_REMOTE_PATH", "/var/log/journal/remote/")
    
        file_max_size = os.environ.get("JOURNAL_REMOTE_MAX_FILE_SIZE", "10") 
        cleanup_interval = os.environ.get("JOURNAL_REMOTE_CLEANUP_INTERVAL", 60 * 60)  # Interval in seconds, default 1 hour
        systemd_thread_timeout = os.environ.get("SYSTEMD_THREAD_TIMEOUT", 2)  # Timeout for systemd journal thread, default 2 seconds
        try:
            self.cleanup_interval = int(cleanup_interval)
        except (ValueError, TypeError) as e:
            self.logger.error(f"Invalid cleanup interval value: {cleanup_interval}. Using default 1 hour. Error: {e}")
            self.cleanup_interval = 60 * 60  # Default to 1 hour if not set or invalid
        try:
            self.file_max_size = int(file_max_size) * 1024 * 1024  # Convert MB to bytes
        except (ValueError, TypeError) as e:
            self.logger.error(f"Invalid file max size value: {file_max_size}. Using default 10 MB. Error: {e}")
            self.file_max_size = 10 * 1024 * 1024  # Default to 10 MB if not set or invalid
        try:
            self.systemd_thread_timeout = int(systemd_thread_timeout)
        except (ValueError, TypeError) as e:
            self.logger.error(f"Invalid systemd thread timeout value: {systemd_thread_timeout}. Using default 2 seconds. Error: {e}")
            self.systemd_thread_timeout = 2

    def _start_journal_remote_service(self):
        """Start the systemd journal-remote service."""
        try:
            self.process = subprocess.Popen([
                "/usr/lib/systemd/systemd-journal-remote",
                "--listen-http=19532",
                f"--output={self.path}",
            ])
            if self.process and self.process.poll() is not None:
                self.logger.error("Failed to start journal-remote.service: Process terminated immediately.")
            with open("/tmp/my_subprocess.pid", "w") as f:
                f.write(str(self.process.pid))
            self.logger.info("journal-remote.service started successfully.")
        except Exception as e:
            self.logger.error(f"Failed to start journal-remote.service: {e}")

    
    def shutdown_journal_remote_service(self, timeout=2):
        if not self.process or self.process.poll() is not None:
            self.logger.warning("No journal remote service process found or it has already terminated.")
            return True
        try:
            self.process.terminate()
            self.process.wait(timeout)
            self.logger.info("Journal remote service terminated successfully.")
            return True
        except subprocess.TimeoutExpired:
            self.logger.debug("Journal remote service did not terminate in time, killing it.")
            self.process.kill()
            try:
                self.process.wait(timeout)
                return True
            except subprocess.TimeoutExpired:
                self.logger.error("Failed to kill journal remote service after timeout.")
        return False


    def _clean_up_journal_logs(self):
        """Clean up old journal logs to prevent disk space issues."""
        def cleanup_journal_logs(file_path):
            self.reader_stop_event.set()  # Ensure the reader is stopped before cleanup
            self.reader_stopped_event.wait()  # Ensure the reader is stopped before cleanup
            result = self.shutdown_journal_remote_service(timeout=4)
            if result:
                try:
                    os.remove(file_path)
                    self.logger.info(f"Removed old journal file: {file_path}")
                except Exception as e:
                    self.logger.error(f"Error removing old journal file {file_path}: {e}")
                self._start_journal_remote_service()
                self.reader_stop_event.clear()  # Signal that the reader can resume
            else:
                self.logger.error("Failed to terminate journal remote service. Not cleaning up old logs.")

        def check_for_clean_up():
            self.logger.info("Starting journal remote service cleanup thread.")
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(self.cleanup_interval)  # Wait for the specified cleanup interval
                if os.path.exists(self.path):
                    for file in os.listdir(self.path):
                        file_path = os.path.join(self.path, file)
                        self.logger.debug(f"Checking file: {file_path}. File size: {os.path.getsize(file_path) if os.path.isfile(file_path) else 'N/A'} bytes")
                        if (os.path.isfile(file_path) 
                            and file.endswith(".journal")
                            and os.path.getsize(file_path) > self.file_max_size
                            ):
                            cleanup_journal_logs(file_path)
                self.logger.debug("Checked for old journal logs to clean up.")

        if self.cleanup_interval <= 0:
            self.logger.warning("Cleanup interval is set to 0 or less. Not starting journal log cleanup thread.")
            return
        thread = threading.Thread(target=check_for_clean_up, daemon=True)
        thread.start()

    def _add_procesor(self, unit):
        if unit in self.processor_instances:
            self.logger.warning(f"Processor for unit {unit} already exists. Skipping creation.")
            return
        processor = LogProcessor(self.logger, 
                                self.config,
                                monitored_object_name=unit,
                                monitor_instance=self,
                                monitor_type="systemd",
                                config_key=unit
                                )   
        self.processor_instances[unit] = {"processor": processor}

    def start(self):
        self._start_journal_remote_service()
        self.reader = journal.Reader(path="/var/log/journal/remote/")
        self.reader.data_threshold = 64 * 1024 * 1024
        self.reader.seek_tail()  # Start at the end of the journal
        self.monitored_units = [u for u in self.config.systemd_services] if self.config.systemd_services else []
        self.processor_instances = {}
        if not self.config.systemd_services:
            logging.warning("No systemd services configured for monitoring. Please check your config.yaml.")
            # return
        
        for unit in self.monitored_units:
            self.reader.add_match(_SYSTEMD_UNIT=unit)
            self._add_procesor(unit)

        self._monitor_systemd_journal()
        if os.environ.get("CLEANUP_JOURNAL_LOGS", "true").strip().lower() == "true":
            self._clean_up_journal_logs()  # Start cleanup thread

        return self._start_message()
    
    def _start_message(self, config_reload=False):
        # Compose and log/send a summary message about monitored services
        monitored_units_message = "\n - ".join(s for s in self.monitored_units)
        message = (
            f"These systemd-services are being monitored:\n - {monitored_units_message}"
            )
        return message
        
    def reload_config(self, config: GlobalConfig):
        self.logger.info("Reloading systemd monitor configuration.")
        # Unmonitor existing services
        selected_units = [u for u in config.systemd_services] if config.systemd_services else []
        try: 
            for unit in [u for u in self.processor_instances if u in selected_units]:
                processor = self.processor_instances[unit]["processor"]
                processor.load_config_variables(self.config)

            # Monitor new services and stop monitoring those not in the new config
            self.reader.flush_matches()  # Clear existing matches
            for unit in selected_units:
                self.reader.add_match(_SYSTEMD_UNIT=unit)
                self._add_procesor(unit)
        except Exception as e:
            self.logger.error(f"Error during systemd monitor configuration reload: {e}")
            return ""
        self.monitored_units = selected_units
        return self._start_message(config_reload=True)
        
    

    def format_entry(self, entry, template="{__REALTIME_TIMESTAMP} {_HOSTNAME} {_SYSTEMD_UNIT}[{_PID}]: {MESSAGE}"):
        timestamp = entry.get('__REALTIME_TIMESTAMP', '')
        if isinstance(timestamp, datetime):
            timestamp = timestamp.strftime("%b %d %H:%M:%S")
        else:
            timestamp = datetime.fromisoformat(timestamp).strftime("%b %d %H:%M:%S")      
        entry['__REALTIME_TIMESTAMP'] = timestamp
        if template:
            return template.format(**entry)

    def process_entry(self, entry):
        """Format the log message from a journal entry."""
        unit = entry.get('_SYSTEMD_UNIT', '')
        message = entry.get('MESSAGE', '')
        hostname = entry.get('_HOSTNAME', '')
        processor_instance = self.processor_instances.get(unit)
        if os.environ.get("DEBUG_SYSTEMD_LOGS", "").strip().lower() == "true":
            log_entry = self.format_entry(entry)
            self.logger.debug(log_entry)

        if processor_instance:
            processor = processor_instance["processor"]
            processor.hostname = hostname
            processor.process_line(message)

    def _monitor_systemd_journal(self):

        def systemd_monitor():
            error_count, last_error_time = 0, time.time()
            while not self.shutdown_event.is_set():
                try:
                    while not self.reader_stop_event.is_set() and not self.shutdown_event.is_set():
                        self.reader_stopped_event.clear()  # Reset the stopped event
                        wait_result = self.reader.wait(timeout=self.systemd_thread_timeout) 
                        if wait_result != journal.APPEND:
                            continue
                        self.reader.process()  
                        
                        for entry in self.reader:
                            self.process_entry(entry)
                            if self.shutdown_event.is_set():
                                self.logger.info("Systemd journal monitoring stopped.")
                                break
                            
                except Exception as e:
                    if self.shutdown_event.is_set():
                        self.logger.info("Systemd journal monitoring stopped. LoggiFly is shutting down.")
                        break
                    self.logger.error(f"Error in systemd journal monitoring: {e}")
                    error_count += 1
                finally:
                    self.reader_stopped_event.set()  # Signal that the reader has stopped
                    if time.time() - last_error_time > 60:
                        error_count = 0
                    last_error_time = time.time()
                    if error_count > 5:
                        self.logger.error("Too many errors in systemd journal monitoring. Exiting.")
                        break
                    time.sleep(1)  # Wait before retrying 

            self.logger.info("Systemd journal monitoring stopped.")
            
            if not self.shutdown_event.is_set():
                self.cleanup()
    
        thread = threading.Thread(target=systemd_monitor, daemon=True)
        thread.start()

    def cleanup(self):
        """Clean up resources."""
        self.logger.info("Cleaning up systemd journal monitor resources.")
        try:
            self.reader.close()
            logging.info("Systemd journal reader closed.")
        except Exception as e:
            self.logger.error(f"Error closing systemd journal reader: {e}")
        
        self.process.terminate()
        self.shutdown_journal_remote_service()

    def tail_logs(self, monitored_object_name, n=10, journal_path="/var/log/journal/remote/", monitor_type="systemd"):
        r = None
        try:
            self.logger.debug(f"Attempting to read the last {n} entries from the journal at {journal_path}")
            r = journal.Reader(path=journal_path)
            r.data_threshold = 64 * 1024 * 1024
            r.add_match(_SYSTEMD_UNIT=monitored_object_name)
            r.seek_tail()
            entries = []
            for _ in range(n):
                entry = r.get_previous()
                if not entry:
                    break
                log_entry = self.format_entry(entry)
                entries.append(log_entry)  
            log_tail = "\n".join(list(reversed(entries)))
            return log_tail
        except OSError as e:
            self.logger.error(f"Can not tail logs for systemd service '{monitored_object_name}': Journal access error: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Can not tail logs for systemd service: Error: {str(e)}")
        finally:
            if r is not None:
                try:
                    r.close()
                except OSError:
                    pass