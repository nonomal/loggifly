import logging
import threading
import socket
import traceback
import time
import os
import random
import re
import requests
import docker
import docker.errors
from datetime import datetime
from notifier import send_notification
from line_processor import LogProcessor
from utils.helpers import parse_labels
from load_config import add_to_config


class MonitoredContainerContext:
    """
    Represents a monitored container with all its associated state.
    This replaces the dictionary-based approach for cleaner, type-safe code.
    """
    def __init__(self, monitor_type, config_key, monitored_object_name, docker_name, container_id):
        self.monitor_type = monitor_type  # "container" or "swarm"
        self.config_key = config_key  # The key used in the configuration
        self.monitored_object_name = monitored_object_name  # Unique name for container (also if it is a swarm service container replica)
        self.docker_name = docker_name  # Actual Docker container name
        self.container_id = container_id  # Docker container ID
        self.generation = 0  # Used to track container restarts
        self.monitor_stop_event = threading.Event()  # Signal to stop monitoring
        self.monitoring_stopped_event = threading.Event()  # Signal that monitoring has stopped
        self.log_stream = None  # Will be set when the log stream is opened
        self.processor = None  # Will be set after initialization
    
    def increment_generation(self):
        """Increment the generation counter when container is restarted."""
        self.generation += 1
        
    def set_processor(self, processor):
        """Set the log processor for this container."""
        self.processor = processor
        
    def set_log_stream(self, stream):
        """Set the log stream for this container."""
        self.log_stream = stream
        
    def clear_log_stream(self):
        """Clear the log stream reference."""
        self.log_stream = None
        
    def stop_monitoring(self):
        """Signal to stop monitoring this container."""
        self.monitor_stop_event.set()
        
    def clear_stop_signal(self):
        """Clear the stop monitoring signal."""
        self.monitor_stop_event.clear()
        
    def is_monitoring_stopped(self):
        """Check if monitoring has been stopped."""
        return self.monitoring_stopped_event.is_set()
        
    def set_monitoring_stopped(self):
        """Signal that monitoring has stopped."""
        self.monitoring_stopped_event.set()
        
    def clear_monitoring_stopped(self):
        """Clear the monitoring stopped signal."""
        self.monitoring_stopped_event.clear()


# class ContainerConfigurationHandler:
#     """
#     Handles the logic for determining if and how a container should be monitored.
#     This centralizes the configuration logic that was previously spread across methods.
#     """
#     def __init__(self, logger, config, swarm_mode, selected_containers, selected_swarm_services):
#         self.logger = logger
#         self.config = config
#         self.swarm_mode = swarm_mode
#         self.selected_containers = selected_containers
#         self.selected_swarm_services = selected_swarm_services

    
#     def get_monitor_context(self, container):
#         """
#         Determine if a container should be monitored and how.
#         Returns a tuple of (monitor_type, configured_name, monitored_object_name) if the container
#         should be monitored, None otherwise.
#         """


class MonitoredContainerRegistry:
    def __init__(self):
        self._by_id = {}
        self._by_config_key = {}
        self._by_monitored_object_name = {}
        self._by_docker_name = {}

    def add(self, container_context):
        monitor_type = container_context.monitor_type
        container_id = container_context.container_id
        monitored_object_name = container_context.monitored_object_name
       
        self._by_id[container_id] = container_context
        self._by_monitored_object_name[(monitor_type, monitored_object_name)] = container_context

    def get_by_id(self, container_id):
        return self._by_id.get(container_id)
    
    def get_by_monitored_object_name(self, monitor_type, monitored_object_name):
        return self._by_monitored_object_name.get((monitor_type, monitored_object_name))
            
    def get_actively_monitored(self, type="all"):
        """
        Returns a list of actively monitored containers.
        """
        swarm_services =[
                container for container in self._by_id.values()
                if not container.is_monitoring_stopped() and container.monitor_type == "swarm"
            ]
        containers = [
                container for container in self._by_id.values()
                if not container.is_monitoring_stopped() and container.monitor_type == "container"
            ]
        if type == "swarm":
            return swarm_services
        elif type == "container":   
            return containers
        else:
            return swarm_services + containers

    def update_id(self, old_id, new_id):
        if (container_context := self._by_id.pop(old_id, None)) is not None:
            container_context.container_id = new_id
            self._by_id[new_id] = container_context

    def values(self):
        return self._by_id.values()

    def __contains__(self, container_context):
        return container_context in self._by_id.values()


class DockerLogMonitor:
    """
    Monitors Docker containers and events for a given host.

    Starts a thread for each monitored container and a thread for Docker event monitoring.
    Handles config reloads, container start/stop, and log processing.
    """
    def __init__(self, config, hostname, host):
        self.hostname = hostname  # empty string if only one client is being monitored, otherwise the hostname of the client do differentiate between the hosts
        self.host = host
        self.config = config
        self.swarm_mode = os.getenv("LOGGIFLY_MODE", "").strip().lower() == "swarm"
        # self.monitor_type = "swarm" if self.swarm_mode else "container"
        self._registry = MonitoredContainerRegistry()
        self.registry_lock = threading.Lock()
        self.event_stream = None

        self.shutdown_event = threading.Event()
        self.cleanup_event = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        
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
        
    def get_service_name(self, labels):
        """
        Tries to extract the service name with their replica id from container labels so that we have a unique name for each replica.
        """
        task_id = labels.get("com.docker.swarm.task.id")
        task_name = labels.get("com.docker.swarm.task.name")
        service_name = labels.get("com.docker.swarm.service.name", "")
        if not any([service_name, task_id, task_name]):
            return None
        # Regex: service_name.<replica>.<task_id>
        pattern = re.escape(service_name) + r"\.(\d+)\." + re.escape(task_id) + r"$"
        regex = re.compile(pattern)
        match = regex.search(task_name)
        if match:
            return f"{service_name}.{match.group(1)}"
        else:
            return service_name

    def _get_swarm_if_selected(self, container, return_configured_name=False):               
        # Return the configured swarm service name if the container belongs to a monitored swarm service
        if container is None:
            return None
        labels = container.labels
        service_name = labels.get("com.docker.swarm.service.name", "")
        stack_name = labels.get("com.docker.stack.namespace", "")
        if service_name or stack_name:
            for configured in self.selected_swarm_services:
                if configured == service_name or configured == stack_name:
                    if return_configured_name:
                        return configured
                    else:
                        return self.get_service_name(labels) or stack_name or container.name
        return None

    def get_monitor_context_if_selected(self, container):
        if self.swarm_mode and (monitored_object_name := self._get_swarm_if_selected(container)):
            configured_name = self._get_swarm_if_selected(container, return_configured_name=True)
            return "swarm", configured_name, monitored_object_name
        
        if container.name in self.selected_containers:
            return "container", container.name, container.name
        
        labels = container.labels
        if labels.get("loggifly.monitor", "false").lower() == "true":
            label_config = parse_labels(labels)
            try:
                if service_name := self.get_service_name(labels):
                    self.logger.info(f"Found swarm service {service_name} with labels: {label_config}")
                    monitor_type, configured_name, monitored_object_name = "swarm", service_name, service_name
                else:
                    self.logger.info(f"Found container {container.name} with labels: {label_config}")
                    monitor_type, configured_name, monitored_object_name = "container", container.name, container.name

                new_config = add_to_config(self.config, monitor_type, configured_name, label_config)
                if new_config:
                    self.logger.debug(f"Added {monitor_type} config based on labels:\n{new_config}")
                    return monitor_type, container.name, container.name, new_config
                else:
                    self.logger.error(f"Error adding label config for container {container.name}")
            except Exception as e:
                self.logger.error(f"Error adding label config for container {container.name}: {e}")
        return None

    def _maybe_monitor_container(self, container, monitor_context=None):
        """
        Check if a container should be monitored based on its name and config.
        Returns True if the container should be monitored, False otherwise.
        """
        # Use the configuration handler to determine if the container should be monitored
        monitor_context = monitor_context or self.get_monitor_context_if_selected(container)
        if not monitor_context:
            return False

        # Unpack the monitor context
        if len(monitor_context) == 4:  # Context includes a new configuration from labels
            monitor_type, configured_name, monitored_object_name, new_config = monitor_context
            # Update the main configuration with the new configuration from labels
            if monitor_type == "swarm":
                self.config.swarm_services[configured_name] = new_config
            else:
                self.config.containers[configured_name] = new_config
        else:
            monitor_type, configured_name, monitored_object_name = monitor_context

        self.logger.info(f"New Container to monitor: {container.name}")

        # Check if we're already monitoring this container
        if container_context := self._registry.get_by_monitored_object_name(monitor_type, monitored_object_name):          
            self.logger.debug(f"{monitored_object_name}: Already in registry.")
            container_context.increment_generation()
            # Close old stream connection to stop old monitoring thread if it exists
            self._close_stream_connection(container_context.container_id)
            if not container_context.monitoring_stopped_event.wait(2):
                self.logger.warning(f"Old monitoring thread for {monitored_object_name} might not have been closed.")
            self.logger.debug(f"{monitored_object_name}: Re-Using old context")
            self._registry.update_id(container_context.container_id, container.id)
            self.logger.debug(f"{monitored_object_name}: Context: {container_context}")
        else:
            # Create a new container context for monitoring
            container_context = MonitoredContainerContext(
                monitor_type,
                configured_name,
                monitored_object_name,
                container.name,
                container.id,
            )
            with self.registry_lock:
                self._registry.add(container_context)
            
            # Create a log processor for this container
            processor = LogProcessor(
                self.logger, 
                self.config, 
                monitored_object_name=monitored_object_name,
                monitor_instance=self,
                container_stop_event=container_context.monitor_stop_event, 
                hostname=self.hostname, 
                monitor_type=monitor_type,
                config_key=configured_name
            )
            # Add the processor to the container context
            container_context.set_processor(processor)

        # Start monitoring the container
        container_context.clear_stop_signal()
        self._monitor_container(container, container_context)
        return True
        
    def _close_stream_connection(self, container_id):
        if not container_id:
            self.logger.debug("No container_id provided to close stream connection.")
            return
        if container_context := self._registry.get_by_id(container_id):
            monitored_object_name = container_context.monitored_object_name
            if stream := container_context.log_stream:
                with self.registry_lock:
                    container_context.stop_monitoring()
                    self.logger.info(f"Closing Log Stream connection for {monitored_object_name}")
                    try:
                        stream.close()
                        container_context.clear_log_stream()
                    except Exception as e:
                        self.logger.warning(f"Error trying do close log stream for {monitored_object_name}: {e}")
            else:
                self.logger.debug(f"No log stream found for container_id ({monitored_object_name}). Nothing to close.")
        else:
            self.logger.debug(f"Could not find container context for container_id {container_id}. Cannot close stream connection.")
   
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
        
        # Initialize the configuration handler with the selected containers and services
        # self.config_handler = ContainerConfigurationHandler(
        #     self.logger,
        #     self.config,
        #     self.swarm_mode,
        #     self.selected_containers,
        #     self.selected_swarm_services
        # )

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
            self._maybe_monitor_container(container)

        self._watch_events()
        return self._start_message()

    def reload_config(self, config):
        """
        Reload configuration and update monitoring for containers.
        Called by ConfigHandler when config.yaml changes or on reconnection.
        Updates keywords and settings in processor instances, starts/stops monitoring as needed.
        """
        self.config = config if config is not None else self.config
        self.logger.setLevel(getattr(logging, self.config.settings.log_level.upper(), logging.INFO))
        self._get_selected_containers()  # This also reinitializes the config_handler
        if self.shutdown_event.is_set():
            self.logger.debug("Shutdown event is set. Not applying config changes.")
            return
        try:
            # stop monitoring containers that are no longer in the config
            actively_monitored_swarm = self._registry.get_actively_monitored(type="swarm")
            actively_monitored_containers = self._registry.get_actively_monitored(type="container") 
            stop_monitoring = (
                [c for c in actively_monitored_swarm if c.config_key not in self.selected_swarm_services]
                + 
                [c for c in actively_monitored_containers if c.config_key not in self.selected_containers]
            )
            # actively_monitored = self._registry.get_actively_monitored(type="all")
            for container_context in stop_monitoring: 
                self._close_stream_connection(container_context.container_id)

            # reload config variables in the line processor instances to update keywords and other settings
            reload_processors = (
                [c for c in self._registry.values() if c.monitor_type == "container" and c.config_key in self.selected_containers]
                + 
                [c for c in self._registry.values() if c.monitor_type == "swarm" and c.config_key in self.selected_swarm_services]
            )
            for context in reload_processors:
                processor = context.processor
                processor.load_config_variables(self.config)
            # start monitoring containers that are in the config but not monitored yet
            for c in self.client.containers.list(): 
                if monitor_context := self.get_monitor_context_if_selected(c):
                    monitor_type, configured_name, monitored_object_name = monitor_context[:3]  # Unpack only the first three elements
                    if (not (context := self._registry.get_by_monitored_object_name(monitor_type, monitored_object_name)) 
                        or context.is_monitoring_stopped()):
                        self.logger.debug(f"Container {c.name} is not monitored yet. Starting monitoring.")
                        self._maybe_monitor_container(c, monitor_context=monitor_context)
                    else:
                        self.logger.debug(f"Container {c.name} is already monitored. Skipping.")

            return self._start_message(config_reload=True)
        except Exception as e:
            self.logger.error(f"Error handling config changes: {e}")
        return ""

    def _start_message(self, config_reload=False):
        # Compose and log/send a summary message about monitored containers and services
        self.logger.debug(f"Selected Containers: {self.selected_containers}")
        monitored_container_names = [c.monitored_object_name for c in self._registry.get_actively_monitored(type="container")]
        self.logger.debug(f"Monitored Container Names: {monitored_container_names}")
        monitored_containers_message = "\n - ".join(monitored_container_names)
        unmonitored_containers = [c for c in self.selected_containers if c not in monitored_container_names]
        self.logger.debug(f"Unmonitored Containers: {unmonitored_containers}")
        message = (
            f"These containers are being monitored:\n - {monitored_containers_message}" if monitored_container_names
            else f"No selected containers are running. Waiting for new containers..."
        )
        message = message + ((f"\n\nThese selected containers are not running:\n - " + '\n - '.join(unmonitored_containers)) if unmonitored_containers else "")
        if self.swarm_mode:
            actively_monitored_swarm = [context for context in self._registry.get_actively_monitored(type="swarm")]
            unmonitored_swarm_services = [
                s for s in self.selected_swarm_services if s not in [s.config_key for s in actively_monitored_swarm]
                ]
            monitored_swarm_service_instances = [s.monitored_object_name for s in actively_monitored_swarm]
            monitored_services_message = "\n - ".join(monitored_swarm_service_instances) if actively_monitored_swarm else ""
            self.logger.debug(f"Monitored Swarm Services: {actively_monitored_swarm}. Unmonitored Swarm Services: {unmonitored_swarm_services}")
            message = (message
                        + (f"\nThese Swarm Services are being monitored:\n - {monitored_services_message}"
                            if actively_monitored_swarm
                            else "")
                        + f"\n\nThese selected Swarm Services are not running:\n - "+ "\n - ".join(unmonitored_swarm_services)
                        )
        if self.hostname:
            message = f"[{self.hostname}]\n" + message
        return message

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
    

    def _monitor_container(self, container, container_context):
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

            nonlocal container_context
            monitor_stop_event = container_context.monitor_stop_event
            monitoring_stopped_event = container_context.monitoring_stopped_event
            gen = container_context.generation  # get the generation of the current thread to check if a new thread is started for this container
            monitored_object_name = container_context.monitored_object_name
            processor = container_context.processor


            while not self.shutdown_event.is_set() and not monitor_stop_event.is_set():
                buffer = b""
                not_found_error = False
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    container_context.set_log_stream(log_stream)  
                    monitoring_stopped_event.clear()
                    self.logger.info(f"{monitored_object_name}: Log Stream started")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            self.logger.error(f"{monitored_object_name}: Buffer overflow detected for container, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                self.logger.warning(f"{monitored_object_name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded:
                                processor.process_line(log_line_decoded)
                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {monitored_object_name} not found during Log Stream: {e}")
                    not_found_error = True
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time, monitored_object_name)
                    if error_count == 1:  # log error only once
                        self.logger.error("Error trying to monitor %s: %s", monitored_object_name, e)
                        self.logger.debug(traceback.format_exc())
                finally:
                    self.logger.debug(f"{monitored_object_name}: Log Stream ended. gen: {gen}\ncontainer_context: {container_context}")
                    if self.shutdown_event.is_set():
                        break
                    if gen != container_context.generation:  # if there is a new thread running for this container this thread stops
                        self.logger.debug(f"{monitored_object_name}: Stopping monitoring thread because a new thread was started for this container.")
                        break
                    elif too_many_errors or not_found_error or check_container(container_start_time, error_count) is False or monitor_stop_event.is_set():
                        self._close_stream_connection(container.id)
                        break
                    else:
                        self.logger.info(f"{monitored_object_name}: Log Stream stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info(f"{monitored_object_name}: Monitoring stopped for container.")
            monitoring_stopped_event.set()  # signal that the monitoring thread has stopped
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
                    self.event_stream = self.client.events(decode=True, filters={"event": ["start", "stop"]}, since=now)
                    self.logger.info("Docker Event Watcher started. Watching for new containers...")
                    for event in self.event_stream:
                        if self.shutdown_event.is_set():
                            self.logger.debug("Shutdown event is set. Stopping event handler.")
                            break
                        container_id = event["Actor"]["ID"]
                        container_name = event["Actor"].get("Attributes", {}).get("name", "")
                        if event.get("Action") == "start":
                            container = self.client.containers.get(container_id)
                            if self._maybe_monitor_container(container):
                                self.logger.info(f"Monitoring new container: {container.name}")
                                if self.config.settings.disable_container_event_message is False:
                                    send_notification(self.config, "Loggifly", "LoggiFly", f"Monitoring new container: {container.name}", hostname=self.hostname)
                        elif event.get("Action") == "stop":
                            if container_id in [c.container_id for c in self._registry.values()]:
                                self.logger.info(f"The Container {container_name or container_id} was stopped. Stopping Monitoring now.")
                                self._close_stream_connection(container_id)
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
            self.event_stream = None
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
        for context in self._registry.get_actively_monitored(type="all"):
            if context.log_stream is not None:
                self._close_stream_connection(context.container_id)
        if self.event_stream:
            try:
                self.event_stream.close()
                self.logger.info("Docker Event Stream closed.")
            except Exception as e:
                self.logger.warning(f"Error while trying to close Docker Event Stream: {e}")

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

    def tail_logs(self, monitored_object_name, monitor_type, lines=10):
        """
        Tail the last 'lines' of logs for a specific container.
        Returns the last 'lines' of logs as a list of strings.
        """
        if monitor_type and (container_context := self._registry.get_by_monitored_object_name(monitor_type, monitored_object_name)):
            if container := self.client.containers.get(container_context.container_id):
                try:
                    logs = container.logs(tail=lines).decode('utf-8')
                    return logs
                except docker.errors.NotFound:
                    logging.error(f"Failed to read last {lines} lines of container logs. Container not found.")
                    return None
                except Exception as e:
                    logging.error(f"Error while trying to tail logs for: {e}")
                    return None
            else:
                self.logger.error(f"Container {monitored_object_name} not found. Cannot tail logs.")
                return None
        else:
            self.logger.error(f"Container {monitored_object_name} not found in registry. Cannot tail logs.\nMonitor Type: {monitor_type}\nself._registry {self._registry.get_actively_monitored(type='all')}")
            return None
        
    def container_action(self, monitored_object_name, action, monitor_type="container"):
        """
        Perform an action on a container (start, stop, restart).
        """        
        if not (container_context := self._registry.get_by_monitored_object_name(monitor_type, monitored_object_name)):
            self.logger.error(f"Container {monitored_object_name} not found in registry. Cannot perform action: {action}")
            return False
        container = self.client.containers.get(container_context.container_id)
        if container:
            try:
                container_name = container.name
                if action == "stop":
                    self.logger.info(f"Stopping Container: {container_name}.")
                    container = container
                    container.stop()
                    if container.wait(timeout=10):
                        container.reload()
                        self.logger.debug(f"Container {container_name} has been stopped: Status: {container.status}")
                elif action == "restart":
                    self.logger.info(f"Restarting Container: {container_name}.")
                    container = container
                    container.restart()
                    container.reload()
                    self.logger.info(f"Container {container_name} has been restarted. Status: {container.status}")

            except Exception as e:
                self.logger.error(f"Failed to {action} {monitored_object_name}: {e}")
                return False
        else:
            self.logger.error(f"Container {monitored_object_name} not found. Could not perform action: {action}")
            return False
