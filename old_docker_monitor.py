import logging
import threading
import socket
import traceback
import time
import os
import random
import requests
import docker
import docker.errors
from datetime import datetime
from notifier import send_notification
from line_processor import LogProcessor

class DockerLogMonitor:
    """
    Monitors Docker containers and events for a given host.

    Starts a thread for each monitored container and a thread for Docker event monitoring.
    Handles config reloads, container start/stop, and log processing.

    Some important Attributes:
    ----------
    processor_instances : dict[str, dict]
        Maps container name to a dict with:
            - 'processor': LogProcessor instance (processes log lines, supports config reloads)
            - 'container_stop_event': threading.Event to signal log monitoring thread shutdown
            - 'generation': int, incremented for each new monitoring thread per container
    stream_connections : dict[str, Any]
        Maps container name to the active log stream connection (used to release blocking log streams and stop threads).
    monitored_containers : dict[str, docker.models.containers.Container]
        Maps container ID to the currently monitored Docker container object.
    selected_containers : list[str]
        Names of containers configured to be monitored for this host.
    selected_swarm_services : list[str]
        Names of swarm services configured to be monitored (if in swarm mode).
    """
    def __init__(self, config, hostname, host):
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client do differentiate between the hosts
        self.host = host
        self.config = config
        self.swarm_mode = os.getenv("LOGGIFLY_MODE", "").strip().lower() == "swarm"

        self.shutdown_event = threading.Event()
        self.cleanup_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.processor_instances = {}
        self.processors_lock = threading.Lock()

        self.stream_connections = {}
        self.stream_connections_lock = threading.Lock()
        self.monitored_containers = {}

    def init_logging(self):
        """
        Configure logger to include hostname for multi-host or swarm setups.
        """
        self.logger = logging.getLogger(f"Monitor-{self.hostname}")
        self.logger.handlers.clear()
        handler = logging.StreamHandler()
        formatter = (
            logging.Formatter(f'%(asctime)s - %(levelname)s - [Host: {self.hostname}] - %(message)s')
            if self.hostname else logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self.logger.propagate = False

    def _add_thread(self, thread):
        with self.threads_lock:
            self.threads.append(thread)

    def _add_processor_instance(self, processor, container_stop_event, container_name):
        with self.processors_lock:
            if container_name not in self.processor_instances:
                self.processor_instances[container_name] = {
                    "processor": processor,
                    "container_stop_event": container_stop_event,
                    "generation": 0
                }
                return True
            else:
                return False

    def _add_stream_connection(self, container_name, connection):
        with self.stream_connections_lock:
            self.stream_connections[container_name] = connection

    def _close_stream_connection(self, container_name):
        # Close and remove the log stream connection for a container
        stream = self.stream_connections.get(container_name)
        container_stop_event = self.processor_instances[container_name]["container_stop_event"]
        container_stop_event.set()
        if stream:
            self.logger.info(f"Closing Log Stream connection for {container_name}")
            try:
                stream.close()
                self.stream_connections.pop(container_name)
            except Exception as e:
                self.logger.warning(f"Error trying do close log stream for {container_name}: {e}")
        else:
            self.logger.debug(f"Could not find log stream connection for container {container_name}")

    def _get_selected_containers(self):
        # Build lists of containers and swarm services to monitor based on config
        self.selected_containers = []
        if self.config.containers:
            for container in self.config.containers:
                container_object = self.config.containers[container]
                # Check if 'hosts' is set and whether the container should be monitored on that host
                if self.hostname and container_object.hosts is not None:
                    hostnames = container_object.hosts.split(",")
                    if all(hn.strip() != self.hostname for hn in hostnames):
                        self.logger.debug(f"Container {container} is configured for host(s) '{', '.join(hostnames)}' but this instance is running on host '{self.hostname}'. Skipping this container.")
                        continue
                self.selected_containers.append(container)

        self.selected_swarm_services = []
        if self.config.swarm_services and self.swarm_mode:
            for swarm in self.config.swarm_services:
                swarm_object = self.config.swarm_services[swarm]
                if self.hostname and swarm_object.hosts is not None:
                    hostnames = swarm_object.hosts.split(",")
                    if all(hn.strip() != self.hostname for hn in hostnames):
                        self.logger.debug(f"Swarm service {swarm} is configured for host(s) '{', '.join(hostnames)}' but this instance is running on host '{self.hostname}'. Skipping this swarm service.")
                        continue
                self.selected_swarm_services.append(swarm)

    def _check_if_swarm_to_monitor(self, container):
        # Return the configured swarm service name if the container belongs to a monitored swarm service
        if container is None:
            return None
        labels = container.labels
        service_name = labels.get("com.docker.swarm.service.name", "")
        if service_name:
            for configured in self.selected_swarm_services:
                if service_name.startswith(configured):
                    return configured
        return None

    # This function is called from outside this class to start the monitoring
    def start(self, client):
        """
        Start monitoring for all configured containers and Docker events using the provided Docker client.
        Handles swarm mode and hostname assignment.
        """
        self.client = client
        if self.swarm_mode:
            # Find out if manager or worker and set hostname to differentiate between the instances
            try:
                swarm_info = client.info().get("Swarm")
                node_id = swarm_info.get("NodeID")
            except Exception as e:
                self.logger.error(f"Could not get info via docker client. Needed to get info about swarm role (manager/worker)")
                node_id = None
            if node_id:
                try:
                    node = client.nodes.get(node_id)
                    manager = True if node.attrs["Spec"]["Role"] == "manager" else False
                except Exception as e:
                    manager = False
                try:
                    self.hostname = ("manager" if manager else "worker") + "@" + self.client.info()["Name"]
                except Exception as e:
                    self.hostname = ("manager" if manager else "worker") + "@" + socket.gethostname()
        self.init_logging()
        if self.swarm_mode:
            self.logger.info(f"Running in swarm mode.")

        self._get_selected_containers()

        for container in self.client.containers.list():
            if self.swarm_mode:
                # if the container belongs to a swarm service that is set in the config the service name has to be saved for later use
                swarm_service_name = self._check_if_swarm_to_monitor(container)
                if swarm_service_name:
                    self.logger.debug(f"Trying to monitor container of swarm service: {swarm_service_name}")
                    self._monitor_container(container, swarm_service=swarm_service_name)
                    self.monitored_containers[container.id] = container
                    continue
            if container.name in self.selected_containers:
                self._monitor_container(container)
                self.monitored_containers[container.id] = container
        self._watch_events()
        self._start_message()

    def reload_config(self, config):
        """
        Reload configuration and update monitoring for containers.
        Called by ConfigHandler when config.yaml changes or on reconnection.
        Updates keywords and settings in processor instances, starts/stops monitoring as needed.
        """
        if self.swarm_mode:
            self.logger.debug("Skipping config reload because of Swarm Mode")
            return
        self.config = config if config is not None else self.config
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self._get_selected_containers()
        if self.shutdown_event.is_set():
            self.logger.debug("Shutdown event is set. Not applying config changes.")
            return
        try:
            # stop monitoring containers that are no longer in the config
            stop_monitoring = [c for _, c in self.monitored_containers.items() if c.name not in self.selected_containers]
            for c in stop_monitoring:
                container_stop_event = self.processor_instances[c.name]["container_stop_event"]
                self._close_stream_connection(c.name)
                self.monitored_containers.pop(c.id)
            # reload config variables in the line processor instances to update keywords and other settings
            for container in self.processor_instances.keys():
                processor = self.processor_instances[container]["processor"]
                processor.load_config_variables(self.config)

            # start monitoring new containers that are in the config but not monitored yet
            containers_to_monitor = [c for c in self.client.containers.list() if c.name in self.selected_containers and c.id not in self.monitored_containers.keys()]
            for c in containers_to_monitor:
                self.logger.info(f"New Container to monitor: {c.name}")
                if self.processor_instances.get(c.name) is not None:
                    container_stop_event = self.processor_instances[c.name]["container_stop_event"]
                    container_stop_event.clear()
                self._monitor_container(c)
                self.monitored_containers[c.id] = c

            self._start_message(config_reload=True)
        except Exception as e:
            self.logger.error(f"Error handling config changes: {e}")

    def _start_message(self, config_reload=False):
        # Compose and log/send a summary message about monitored containers and services
        monitored_containers_message = "\n - ".join(c.name for id, c in self.monitored_containers.items())
        unmonitored_containers = [c for c in self.selected_containers if c not in [c.name for id, c in self.monitored_containers.items()]]
        message = (
            f"These containers are being monitored:\n - {monitored_containers_message}" if self.monitored_containers
            else f"No selected containers are running. Waiting for new containers..."
        )
        message = message + ((f"\n\nThese selected containers are not running:\n - " + '\n - '.join(unmonitored_containers)) if unmonitored_containers else "")
        if self.swarm_mode:
            monitored_swarm_services = []
            for c in self.monitored_containers.values():
                swarm_label = self._check_if_swarm_to_monitor(c)
                if swarm_label:
                    monitored_swarm_services.append(swarm_label)
            unmonitored_swarm_services = [s for s in self.selected_swarm_services if s not in monitored_swarm_services]
            message = message + ((f"\n\nThese selected Swarm Services are not running:\n - " + '\n - '.join(unmonitored_swarm_services)) if unmonitored_swarm_services else "")

        title = f"LoggiFly: The config file was reloaded" if config_reload else f"LoggiFly started"

        self.logger.info(title + "\n" + message)
        if ((self.config.settings.disable_start_message is False and config_reload is False)
            or (config_reload is True and self.config.settings.disable_config_reload_message is False)):
            send_notification(
                self.config,
                container_name="LoggiFly",
                title=title,
                hostname=self.hostname,
                message=message
            )

    def _handle_error(self, error_count, last_error_time, container_name=None):
        """
        Handle errors for event and log stream threads.
        Stops threads on repeated errors and triggers cleanup if Docker host is unreachable.
        """
        MAX_ERRORS = 5
        ERROR_WINDOW = 60
        now = time.time()
        error_count = 0 if now - last_error_time > ERROR_WINDOW else error_count + 1
        last_error_time = now

        if error_count > MAX_ERRORS:
            if container_name:
                self.logger.error(f"Too many errors for {container_name}. Count: {error_count}")
            else:
                self.logger.error(f"Too many errors for Docker Event Watcher. Count: {error_count}")
            disconnected = False
            try:
                if not self.client.ping():
                    disconnected = True
            except Exception as e:
                logging.error(f"Error while trying to ping Docker Host {self.host}: {e}")
                disconnected = True
            if disconnected and not self.shutdown_event.is_set():
                self.logger.error(f"Connection lost to Docker Host {self.host} ({self.hostname if self.hostname else ''}).")
                self.cleanup(timeout=30)
            return error_count, last_error_time, True  # True = to_many_errors (break while loop)

        time.sleep(random.uniform(0.9, 1.2) * error_count)  # to prevent all threads from trying to reconnect at the same time
        return error_count, last_error_time, False

    def _monitor_container(self, container, swarm_service=None):
        def check_container(container_start_time, error_count):
            """
            Check if the container is still running and matches the original start time.
            Used to stop monitoring if the container is stopped or replaced.
            """
            try:
                container.reload()
                if container.status != "running":
                    self.logger.debug(f"Container {container.name} is not running. Stopping monitoring.")
                    return False
                if container.attrs['State']['StartedAt'] != container_start_time:
                    self.logger.debug(f"Container {container.name}: Stopping monitoring for old thread.")
                    return False
            except docker.errors.NotFound:
                self.logger.error(f"Container {container.name} not found during container check. Stopping monitoring.")
                return False
            except requests.exceptions.ConnectionError as ce:
                if error_count == 1:
                    self.logger.error(f"Can not connect to Container {container.name} {ce}")
            except Exception as e:
                if error_count == 1:
                    self.logger.error(f"Error while checking container {container.name}: {e}")
            return True

        def log_monitor():
            """
            Stream logs from a container and process each line with a LogProcessor instance.
            Handles buffering, decoding, and error recovery.
            """
            container_start_time = container.attrs['State']['StartedAt']
            self.logger.info(f"Monitoring for Container started: {container.name}")
            error_count, last_error_time = 0, time.time()
            too_many_errors = False

            # re-use old line processor instance if it exists, otherwise create a new one
            if container.name in self.processor_instances:
                self.logger.debug(f"{container.name}: Re-Using old line processor")
                with self.processors_lock:
                    self.processor_instances[container.name]["generation"] += 1
                    processor = self.processor_instances[container.name]["processor"]
                    container_stop_event = self.processor_instances[container.name]["container_stop_event"]
                self._close_stream_connection(container.name)  # close old stream connection if it exists
                container_stop_event.clear()
                processor._start_flush_thread()
            else:
                container_stop_event = threading.Event()
                processor = LogProcessor(self.logger, self.hostname, self.config, container, container_stop_event, swarm_service=swarm_service)
                self._add_processor_instance(processor, container_stop_event, container.name)
                container_stop_event.clear()
            gen = self.processor_instances[container.name]["generation"]
            while not self.shutdown_event.is_set() and not container_stop_event.is_set():
                buffer = b""
                not_found_error = False
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    self._add_stream_connection(container.name, log_stream)
                    self.logger.info(f"{container.name}: Log Stream started")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            self.logger.error(f"{container.name}: Buffer overflow detected for container, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                self.logger.warning(f"{container.name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded:
                                processor.process_line(log_line_decoded)
                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {container} not found during Log Stream: {e}")
                    not_found_error = True
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time, container.name)
                    if error_count == 1:  # log error only once
                        self.logger.error("Error trying to monitor %s: %s", container.name, e)
                        self.logger.debug(traceback.format_exc())
                finally:
                    if self.shutdown_event.is_set():
                        break
                    if gen != self.processor_instances[container.name]["generation"]:  # if there is a new thread running for this container this thread stops
                        break
                    elif too_many_errors or not_found_error or check_container(container_start_time, error_count) is False or container_stop_event.is_set():
                        self._close_stream_connection(container.name)
                        break
                    else:
                        self.logger.info(f"{container.name}: Log Stream stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info(f"{container.name}: Monitoring stopped for container.")

        thread = threading.Thread(target=log_monitor, daemon=True)
        self._add_thread(thread)
        thread.start()

    def _watch_events(self):
        """
        Monitor Docker events to start/stop monitoring containers based on the config as they are started or stopped.
        """
        def event_handler():
            error_count = 0
            last_error_time = time.time()
            while not self.shutdown_event.is_set():
                now = time.time()
                too_many_errors = False
                container = None
                try:
                    event_stream = self.client.events(decode=True, filters={"event": ["start", "stop"]}, since=now)
                    self.logger.info("Docker Event Watcher started. Watching for new containers...")
                    for event in event_stream:
                        if self.shutdown_event.is_set():
                            self.logger.debug("Shutdown event is set. Stopping event handler.")
                            break
                        container_id = event["Actor"]["ID"]
                        if event.get("Action") == "start":
                            container = self.client.containers.get(container_id)
                            swarm_label = self._check_if_swarm_to_monitor(container) if self.swarm_mode else None
                            if swarm_label or container.name in self.selected_containers:
                                self._monitor_container(container, swarm_service=swarm_label)
                                self.logger.info(f"Monitoring new container: {container.name}")
                                if self.config.settings.disable_container_event_message is False:
                                    send_notification(self.config, "Loggifly", "LoggiFly", f"Monitoring new container: {container.name}", hostname=self.hostname)
                                self.monitored_containers[container.id] = container
                        elif event.get("Action") == "stop":
                            if container_id in self.monitored_containers:
                                container = self.monitored_containers.get(container_id)
                                if container:
                                    self.logger.info(f"The Container {container.name} was stopped. Stopping Monitoring now.")
                                    self.monitored_containers.pop(container_id)
                                    self._close_stream_connection(container.name)
                except docker.errors.NotFound as e:
                    self.logger.error(f"Docker Event Handler: Container {container} not found: {e}")
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time)
                    if error_count == 1:
                        self.logger.error(f"Docker Event-Handler was stopped {e}. Trying to restart it.")
                finally:
                    if self.shutdown_event.is_set() or too_many_errors:
                        self.logger.debug("Docker Event Watcher is shutting down.")
                        break
                    else:
                        self.logger.info(f"Docker Event Watcher stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info("Docker Event Watcher stopped.")

        thread = threading.Thread(target=event_handler, daemon=True)
        self._add_thread(thread)
        thread.start()

    def cleanup(self, timeout=1.5):
        """
        Clean up all monitoring threads and connections on shutdown or error wheh client is unreachable.
        Closes log streams, joins threads, and closes the Docker client.
        """
        self.logger.info(f"Starting cleanup " f"for host {self.hostname}..." if self.hostname else "...")
        self.cleanup_event.set()
        self.shutdown_event.set()
        with self.stream_connections_lock:
            for container, _ in self.stream_connections.copy().items():
                self._close_stream_connection(container)

        with self.threads_lock:
            alive_threads = []
            for thread in self.threads:
                if thread is not threading.current_thread() and thread.is_alive():
                    thread.join(timeout=timeout)
                    if thread.is_alive():
                        self.logger.debug(f"Thread {thread.name} was not stopped")
                        alive_threads.append(thread)
            self.threads = alive_threads
        try:
            self.client.close()
            self.logger.info("Shutdown completed")
        except Exception as e:
            self.logger.warning(f"Error while trying do close docker client connection during cleanup: {e}")

        self.cleanup_event.clear()
        # self.logger.debug(f"Threads still alive {len(alive_threads)}: {alive_threads}")
        # self.logger.debug(f"Threading Enumerate: {threading.enumerate()}")