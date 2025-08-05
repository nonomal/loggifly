import os
import sys
import time
import signal
import threading
import logging
import traceback
import docker
import docker.errors
from threading import Timer
from docker.tls import TLSConfig
from urllib.parse import urlparse
from pydantic import ValidationError
from typing import Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config.load_config import load_config, format_pydantic_error
from docker_monitor import DockerLogMonitor
from notifier import send_notification

# from systemd_monitor import SystemdMonitor

logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)    
logging.getLogger("docker").setLevel(logging.INFO)
logging.getLogger("watchdog").setLevel(logging.WARNING)


def create_handle_signal(monitor_instances, config, config_observer):
    global_shutdown_event = threading.Event()   

    def handle_signal(signum, frame):
        if not config.settings.disable_shutdown_message:
            send_notification(config=config,
                            entity_name= "LoggiFly",
                            title="LoggiFly", 
                            message="Shutting down")
        if config_observer is not None:
            config_observer.stop()
            config_observer.join()
        threads = []
        for monitor in monitor_instances:
            monitor.shutdown_event.set()
            thread = threading.Thread(target=monitor.cleanup)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join(timeout=2)    
        global_shutdown_event.set()

    return handle_signal, global_shutdown_event
    

class ConfigHandler(FileSystemEventHandler):
    """
    Handles config.yaml changes by reloading configuration and updating all DockerLogMonitor instances.
    Ensures new keywords, settings, or other changes are applied, especially for keyword searching in line_processor.py.
    """
    def __init__(self, monitor_instances, config):
        self.monitor_instances = monitor_instances  
        self.last_config_reload_time = 0
        self.config = config
        self.reload_timer = None
        self.debounce_seconds = 2

    def on_modified(self, event):
        # Debounced reload of config.yaml if reload_config is enabled
        if self.config.settings.reload_config and not event.is_directory:
            if os.path.basename(event.src_path) == "config.yaml":
                if self.reload_timer:
                    self.reload_timer.cancel()
                self.reload_timer = Timer(self.debounce_seconds, self._trigger_reload)
                self.reload_timer.start()

    def _trigger_reload(self):
        logging.info("Config change detected, reloading config...")
        try:
            self.config, _ = load_config()
        except ValidationError as e:
            logging.critical(f"Error reloading config (using old config): {format_pydantic_error(e)}")
            return
        messages = []
        for monitor in self.monitor_instances:
            messages.append(monitor.reload_config(self.config))
        message_line_break = "\n\n" + "-" * 60 + "\n\n"
        message = message_line_break.join(messages) if messages else "LoggiFly is not mointoring anything."
        message = "-" * 60 + "\n" + message + "\n" + "-" * 60

        logging.info(f"Config reloaded successfully.\n{message}")
        if self.config.settings.disable_config_reload_message is False:
            send_notification(
                config=self.config,
                entity_name="LoggiFly",
                title="LoggiFly: The config file was reloaded",
                message=message
            )
        # Reminder: The config watcher remains active even if reload_config is set to False after reload.

def start_config_watcher(monitor_instances, config, path):
    """
    Starts a watchdog observer to monitor config.yaml for changes and trigger reloads.
    """
    observer = Observer()
    observer.schedule(ConfigHandler(monitor_instances, config), path=path, recursive=False)
    observer.start()
    return observer
    

def check_monitor_status(docker_hosts, global_shutdown_event):
    """
    Periodically checks Docker host connections and attempts reconnection if lost.
    """
    def check_and_reconnect():
        while True:
            time.sleep(60)
            for host, values in docker_hosts.items():
                monitor = values["monitor"]
                if monitor.shutdown_event.is_set():
                    while monitor.cleanup_event.is_set():
                        time.sleep(1)
                    if global_shutdown_event.is_set():
                        return
                    tls_config, label = values["tls_config"], values["label"]
                    new_client = None
                    try:    
                        new_client = docker.DockerClient(base_url=host, tls=tls_config)
                    except docker.errors.DockerException as e:
                        logging.warning(f"Could not reconnect to {host} ({label}): {e}")
                    except Exception as e:
                        logging.warning(f"Could not reconnect to {host} ({label}). Unexpected error creating Docker client: {e}")
                    if new_client:
                        logging.info(f"Successfully reconnected to {host} ({label})")
                        monitor.shutdown_event.clear()
                        monitor.start(new_client)
                        monitor.reload_config(None)

    thread = threading.Thread(target=check_and_reconnect, daemon=True)
    thread.start()
    return thread


def create_docker_clients() -> dict[str, dict[str, Any]]:
    """
    Creates Docker clients for all hosts specified in the DOCKER_HOST environment variable and the local Docker socket.
    Searches for TLS certificates in '/certs/{ca,cert,key}.pem' or '/certs/{host}/{ca,cert,key}.pem'.
    Returns a dictionary mapping host to client, TLS config, and label.
    """
    def get_tls_config(hostname):
        cert_locations = [
            (os.path.join("/certs", hostname)),   
            (os.path.join("/certs"))             
        ]

        for cert_dir in cert_locations:
            logging.debug(f"Checking TLS certs for {hostname} in {cert_dir}")
            ca = os.path.join(cert_dir, "ca.pem")
            cert = os.path.join(cert_dir, "cert.pem")
            key = os.path.join(cert_dir, "key.pem")
            
            if all(os.path.exists(f) for f in [ca, cert, key]):
                logging.debug(f"Found TLS certs for {hostname} in {cert_dir}")
                return TLSConfig(client_cert=(cert, key), ca_cert=ca, verify=True)
        return None

    docker_host = os.environ.get("DOCKER_HOST", "")
    logging.debug(f"Environment variable DOCKER_HOST: {os.environ.get('DOCKER_HOST', ' - Not configured - ')}")
    tmp_hosts = [h.strip() for h in docker_host.split(",") if h.strip()]
    hosts = []
    for host in tmp_hosts:
        label = None
        if "|" in host:
            host, label = host.split("|", 1)
        hosts.append((host, label.strip()) if label else (host.strip(), None))

    if os.path.exists("/var/run/docker.sock"):
        logging.debug(f"Path to docker socket exists: True")
        if not any(h[0] == "unix:///var/run/docker.sock" for h in hosts):
            hosts.append(("unix:///var/run/docker.sock", None)) 

    logging.debug(f"Configured docker hosts to connect to: {[host for (host, _) in hosts]}")

    if len(hosts) == 0:
        logging.critical("No docker hosts configured. Please set the DOCKER_HOST environment variable or mount your docker socket.")


    docker_hosts = {}
    for host, label in hosts:
        logging.info(f"Trying to connect to docker client on host: {host}")
        parsed = urlparse(host)
        tls_config = None
        if parsed.scheme == "unix":
            pass  # No TLS for local socket
        elif parsed.scheme == "tcp":
            hostname = parsed.hostname
            tls_config = get_tls_config(hostname)
        try:
            if "podman" in host:
                # Podman workaround: set short timeout for initial ping, then increase for log streaming.
                client = docker.DockerClient(base_url=host, tls=tls_config, timeout=10)
                if client.ping():
                    logging.info(f"Successfully connected to Podman client on {host}")
                    client.close()
                    client = docker.DockerClient(base_url=host, tls=tls_config, timeout=300)
            else:
                client = docker.DockerClient(base_url=host, tls=tls_config, timeout=10)
            docker_hosts[host] = {"client": client, "tls_config": tls_config, "label": label}
        except docker.errors.DockerException as e:
            logging.error(f"Error creating Docker client for {host}: {e}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error creating Docker client for {host}: {e}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
            continue
        
    if len(docker_hosts) == 0:
        logging.critical("Could not connect to any docker hosts. Please check your DOCKER_HOST environment variable or mounted docker socket.")
        logging.info("Waiting 10s to prevent restart loop...")
        time.sleep(10)
        sys.exit(1)
    logging.info(f"Connections to Docker-Clients established for {', '.join([host for host in docker_hosts.keys()])}"
                 if len(docker_hosts.keys()) > 1 else "Connected to Docker Client")
    return docker_hosts


def start_loggifly():
    """
    Main entry point for LoggiFly. Loads config, sets up Docker clients, monitoring, config watcher, and signal handlers.
    """
    try:
        config, path = load_config()
    except ValidationError as e:
        logging.critical(f"Error loading Config: {format_pydantic_error(e)}")
        logging.info("Waiting 15s to prevent restart loop...")
        time.sleep(15)
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, config.settings.log_level.upper(), logging.INFO))
    logging.info(f"Log-Level set to {config.settings.log_level}")
    start_messages = []
    docker_hosts = create_docker_clients()
    hostname = ""
    for number, (host, values) in enumerate(docker_hosts.items(), start=1):
        client, label = values["client"], values["label"]
        if len(docker_hosts.keys()) > 1:
            try:
                hostname = label if label else client.info()["Name"]
            except Exception as e:
                hostname = f"Host-{number}"
                logging.warning(
                    f"Could not get hostname for {host}. LoggiFly will call this host '{hostname}' in notifications and logging to differentiate it from other hosts."
                    f"\nThis may occur if using a Socket Proxy without 'INFO=1', or you can set a label in DOCKER_HOST as 'tcp://host:2375|label'."
                    f"\nError details: {e}")    
                                
        logging.info(f"Starting monitoring for {host} {'(' + hostname + ')' if hostname else ''}")
        monitor = DockerLogMonitor(config, hostname, host)
        start_messages.append(monitor.start(client))
        docker_hosts[host]["monitor"] = monitor

    monitor_instances = [docker_hosts[host]["monitor"] for host in docker_hosts.keys()]
    
    # if os.environ.get("ENABLE_JOURNAL_REMOTE", "").strip().lower() == "true":
    #     logging.info("Systemd journal remote monitoring enabled via environment variable.")
    #     if config.systemd_services:
    #         logging.debug("Trying to start systemd journal monitoring...")
    #         systemd_monitor = SystemdMonitor(config)
    #         start_messages.append(systemd_monitor.start())
    #         monitor_instances.append(systemd_monitor)
    #     else:  
    #         logging.warning("No systemd services configured in config.yaml. Systemd journal monitoring will not start.")
            
    message_line_break = "\n\n" + "-" * 60 + "\n\n"
    message = message_line_break.join(start_messages) if start_messages else "LoggiFly started without mointoring anything."
    message = "-" * 60 + "\n" + message + "\n\n" + "-" * 60

    logging.info(f"LoggiFly started.\n{message}")
    if config.settings.disable_start_message is False:
        send_notification(
            config=config,
            entity_name="LoggiFly",
            title="LoggiFly started",
            message=message
        )
    # Start config observer to catch config.yaml changes
    if config.settings.reload_config and isinstance(path, str) and os.path.exists(path):
        config_observer = start_config_watcher(monitor_instances, config, path)
    else:
        logging.debug("Config watcher not started: reload_config is False or config path invalid.")
        config_observer = None
    
    handle_signal, global_shutdown_event = create_handle_signal(monitor_instances, config, config_observer)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)   

    # Start the thread that checks whether the docker hosts are still monitored and tries to reconnect if the connection is lost.
    check_monitor_status(docker_hosts, global_shutdown_event)
    return global_shutdown_event


if __name__ == "__main__":
    global_shutdown_event = start_loggifly()
    global_shutdown_event.wait()
    
