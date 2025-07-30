import logging
import threading
import socket
import traceback
import time
import os
import random
import re
import requests
from enum import Enum
import docker
import docker.errors
from datetime import datetime
from notifier import send_notification
from line_processor import LogProcessor
from config.load_config import validate_entity_config, get_pretty_yaml_config
from utils import generate_message
from collections import namedtuple
from constants import (
    MonitorType, 
    MonitorDecision, 
    ACTION_STOP, 
    ACTION_RESTART
)



SelectedContainer = namedtuple('SelectedContainer', ['container', 'via_labels'])
SelectedService = namedtuple('SelectedService', ['service', 'via_labels'])

# MonitoringDecision = namedtuple('MonitoringDecision', ['decision', 'source'])

class MonitorConfig:
    def __init__(self, monitor_type, config_key, entity_name, entity_config, config_via_labels=False):
        self.monitor_type = monitor_type  # MonitorType.CONTAINER or MonitorType.SWARM
        self.config_key = config_key  # The key used in the configuration (for swawrm it can be stack or service name)
        self.entity_name = entity_name  # Unique name for container/service (also if it is a swarm service container replica)
        self.entity_config = entity_config  # Will be set after initialization
        self.config_via_labels = config_via_labels  # True if the context was created from labels, False if it was created from config

class MonitoredContainerContext(MonitorConfig):
    """
    Represents a monitored container with all its associated state.
    This replaces the dictionary-based approach for cleaner, type-safe code.
    """
    def __init__(self, monitor_type, config_key, entity_name, container_name, container_id, entity_config, config_via_labels):
        super().__init__(monitor_type, config_key, entity_name, entity_config, config_via_labels)
        self.container_name = container_name  # Actual Docker container name
        self.container_id = container_id  # Docker container ID
        self.generation = 0  # Used to track container restarts
        self.stop_monitoring_event = threading.Event()  # Signal to stop monitoring
        self.monitoring_stopped_event = threading.Event()  # Signal that monitoring has stopped
        self.log_stream = None  # Will be set when the log stream is opened
        self.processor = None  # Will be set after initialization

    @classmethod
    def from_monitor_config(cls, monitor_config, container_name, container_id):
        return cls(
            monitor_type=monitor_config.monitor_type,
            config_key=monitor_config.config_key,
            entity_name=monitor_config.entity_name,
            container_name=container_name,
            container_id=container_id,
            entity_config=monitor_config.entity_config,
            config_via_labels=monitor_config.config_via_labels
        )   

    def set_processor(self, processor):
        self.processor = processor
                        
    def is_monitoring_stopped(self):
        return self.monitoring_stopped_event.is_set()
    
    def update_config(self, entity_config):
        self.entity_config = entity_config
        
class MonitoredContainerRegistry:
    def __init__(self):
        self._by_id = {}
        self._by_config_key = {}
        self._by_entity_name = {}
        self._by_container_name = {}

    def add(self, container_context):
        monitor_type = container_context.monitor_type
        container_id = container_context.container_id
        entity_name = container_context.entity_name
       
        self._by_id[container_id] = container_context
        self._by_entity_name[(monitor_type, entity_name)] = container_context

    def get_by_id(self, container_id):
        return self._by_id.get(container_id)
    
    def get_by_entity_name(self, monitor_type, entity_name):
        return self._by_entity_name.get((monitor_type, entity_name))
            
    def get_actively_monitored(self, monitor_type=None):
        """
        Returns a list of actively monitored containers.
        
        Args:
            monitor_type: Either "all", MonitorType.CONTAINER, or MonitorType.SWARM
        """
        swarm_services =[
                container for container in self._by_id.values()
                if not container.is_monitoring_stopped() and container.monitor_type == MonitorType.SWARM
            ]
        containers = [
                container for container in self._by_id.values()
                if not container.is_monitoring_stopped() and container.monitor_type == MonitorType.CONTAINER
            ]
        if monitor_type == MonitorType.SWARM:
            return swarm_services
        elif monitor_type == MonitorType.CONTAINER:   
            return containers
        else:
            return swarm_services + containers

    def update_id(self, old_id, new_id):
        if (container_context := self._by_id.pop(old_id, None)) is not None:
            container_context.container_id = new_id
            self._by_id[new_id] = container_context

    def values(self):
        return self._by_id.values()
    
    def list_ids(self):
        return [container.container_id for container in self._by_id.values()]

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
        self.selected_containers = []
        self.selected_swarm_services = []
        
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

    def _get_selected_containers(self):
        # Build lists of containers and swarm services to monitor based on config
        self.selected_containers = []
        self.selected_swarm_services = []
        for (config, selected, type_placeholder) in [
            (self.config.containers, self.selected_containers, "Container"),
            (self.config.swarm_services, self.selected_swarm_services, "Swarm Service")
        ]:
            if config:
                for object_name in config:
                    config_object = config[object_name]
                    if self.hostname and config_object.hosts is not None:
                        hostnames = config_object.hosts.split(",")
                        if all(hn.strip() != self.hostname for hn in hostnames):
                            self.logger.debug(f"{type_placeholder} {object_name} is configured for host(s) '{', '.join(hostnames)}' but this instance is running on host '{self.hostname}'. Skipping this {type_placeholder}.")
                            continue
                    selected.append(object_name)

    def _check_monitor_label(self, labels):
        """Extract and check the 'loggifly.monitor' label value"""
        if labels is None:
            return MonitorDecision.UNKNOWN
        monitor_value = labels.get("loggifly.monitor", "").lower().strip()
        if not monitor_value:
            return MonitorDecision.UNKNOWN            
        if monitor_value == "true":
            return MonitorDecision.MONITOR
        elif monitor_value == "false":
            return MonitorDecision.SKIP
            
        return MonitorDecision.UNKNOWN

    def _get_service_info(self, container):
        if not (service_id := container.labels.get("com.docker.swarm.service.id")):
            return None
        try:
            service = self.client.services.get(service_id)
            service_name = service.attrs["Spec"]["Name"]
            stack_name = service.attrs["Spec"]["Labels"].get("com.docker.stack.namespace", "")
            service_labels = service.attrs["Spec"]["Labels"]
            return service_name, stack_name, service_labels
        except Exception as e:
            self.logger.error(f"Error getting service info for container {container.name}: {e}")
            return None

    def should_monitor(self, container, skip_labels=False):
        if socket.gethostname() == container.id[:12]:
            self.logger.debug("LoggiFly can not monitor itself. Skipping.")
            return None

        # Check if the container is a swarm service
        if service_info := self._get_service_info(container):
            service_name, stack_name, service_labels = service_info
            entity_name = get_service_entity_name(container.labels) or container.name
            decision = self._check_monitor_label(service_labels) if not skip_labels else MonitorDecision.UNKNOWN
            if decision == MonitorDecision.MONITOR:
                parsed_config = parse_label_config(service_labels)
                entity_config = validate_entity_config(MonitorType.SWARM, parsed_config)
                if entity_config is None:
                    self.logger.error(f"Could not validate swarm service {service_name} config from labels. Skipping.\nLabels: {service_labels}")
                    return None
                self.logger.info(f"Validated swarm service {service_name} config from labels:\n{get_pretty_yaml_config(entity_config)}")
                return MonitorConfig(MonitorType.SWARM, service_name, entity_name, entity_config, config_via_labels=True)
            elif decision == MonitorDecision.SKIP:
                return None
            elif decision == MonitorDecision.UNKNOWN:
                if service_name in self.selected_swarm_services:
                    decision = MonitorDecision.MONITOR
                    return MonitorConfig(MonitorType.SWARM, service_name, entity_name, self.config.swarm_services[service_name])
                elif stack_name in self.selected_swarm_services:
                    decision = MonitorDecision.MONITOR
                    return MonitorConfig(MonitorType.SWARM, stack_name, entity_name, self.config.swarm_services[stack_name])
        # Check if the container is configured via labels
        labels = container.labels or {}
        decision = self._check_monitor_label(labels) if not skip_labels else MonitorDecision.UNKNOWN
        if decision == MonitorDecision.MONITOR:
            parsed_config = parse_label_config(labels)
            entity_config = validate_entity_config(MonitorType.CONTAINER, parsed_config)
            if entity_config is None:
                self.logger.error(f"Could not validate container {container.name} config from labels. Skipping.\nLabels: {labels}")
                return None
            self.logger.info(f"Validated container {container.name} config from labels:\n{get_pretty_yaml_config(entity_config)}")
            return MonitorConfig(MonitorType.CONTAINER, container.name, container.name, entity_config, config_via_labels=True)
        elif decision == MonitorDecision.SKIP:
            return None
        # Check if the container is configured via normal configuration
        elif decision == MonitorDecision.UNKNOWN and container.name in self.selected_containers:
            decision = MonitorDecision.MONITOR
            return MonitorConfig(MonitorType.CONTAINER, container.name, container.name, self.config.containers[container.name])
        return None

    def _maybe_monitor_container(self, container, monitor_config=None):
        """
        Check if a container should be monitored based on its name and config.
        Returns True if the container should be monitored, False otherwise.
        """
        monitor_config = monitor_config or self.should_monitor(container)
        if monitor_config is None:
            return False
        
        # Start monitoring the container
        container_context = self.prepare_monitored_container_context(container, monitor_config)
        container_context.stop_monitoring_event.clear()
        self._start_monitoring_thread(container, container_context)
        return True

    def prepare_monitored_container_context(self, container, monitor_context):
        # Check if we already have a context for this container and maybe stop the old monitoring thread
        if container_context := self._registry.get_by_entity_name(monitor_context.monitor_type, monitor_context.entity_name):   
            # Close old stream connection to stop old monitoring thread if it exists
            self._close_stream_connection(container_context.container_id)
            if not container_context.monitoring_stopped_event.wait(2):
                self.logger.warning(f"Old monitoring thread for {monitor_context.entity_name} might not have been closed.")
            self.logger.debug(f"{monitor_context.entity_name}: Re-Using old context")
            container_context.update_config(monitor_context.entity_config)
            container_context.processor.load_config_variables(self.config, monitor_context.entity_config)
            container_context.generation += 1
            container_context.stop_monitoring_event.clear()
            self._registry.update_id(container_context.container_id, container.id)
        else:
            # Create a new container context for monitoring
            container_context = MonitoredContainerContext.from_monitor_config(monitor_context, container.name, container.id)
            with self.registry_lock:
                self._registry.add(container_context)
            # Create a log processor for this container
            processor = LogProcessor(
                self.logger, 
                self.config, 
                entity_name=monitor_context.entity_name,
                monitor_instance=self,
                container_stop_event=container_context.stop_monitoring_event, 
                hostname=self.hostname, 
                monitor_type=monitor_context.monitor_type,
                entity_config=monitor_context.entity_config
            )
            # Add the processor to the container context
            container_context.set_processor(processor)
        return container_context
        
    def _close_stream_connection(self, container_id):
        if not container_id:
            self.logger.debug("No container_id provided to close stream connection.")
            return
        if container_context := self._registry.get_by_id(container_id):
            entity_name = container_context.entity_name
            if stream := container_context.log_stream:
                with self.registry_lock:
                    container_context.stop_monitoring_event.set()
                    self.logger.info(f"Closing Log Stream connection for {entity_name}")
                    try:
                        stream.close()
                        container_context.log_stream = None
                    except Exception as e:
                        self.logger.warning(f"Error trying do close log stream for {entity_name}: {e}")
            else:
                self.logger.debug(f"No log stream found for container {entity_name}. Nothing to close.")
        else:
            self.logger.debug(f"Could not find container context for container_id {container_id}. Cannot close stream connection.")
           
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
        self._get_selected_containers()  
        if self.shutdown_event.is_set():
            self.logger.debug("Shutdown event is set. Not applying config changes.")
            return
        try:
            # stop monitoring containers that are no longer in the config and update config in line processor instances
            for context in self._registry.get_actively_monitored():
                if not context.config_via_labels:
                    if context.monitor_type == MonitorType.CONTAINER:
                        if context.config_key not in self.selected_containers:
                            self.logger.debug(f"Container {context.config_key} is not in the config. Stopping monitoring.")
                            self._close_stream_connection(context.container_id)
                        else:
                            context.update_config(self.config.containers[context.config_key])
                            context.processor.load_config_variables(self.config, context.entity_config)
                    elif context.monitor_type == MonitorType.SWARM:
                        if context.config_key not in self.selected_swarm_services:
                            self.logger.debug(f"Swarm Service {context.config_key} is not in the config. Stopping monitoring.")
                            self._close_stream_connection(context.container_id)
                        else:
                            context.update_config(self.config.swarm_services[context.config_key])
                            context.processor.load_config_variables(self.config, context.entity_config)
            # start monitoring containers that are in the config but not monitored yet
            for c in self.client.containers.list(): 
                # Only start monitoring containers that are newly added to the config.yaml and not configured via labels
                if (monitor_config := self.should_monitor(c, skip_labels=True)):
                    monitor_type = monitor_config.monitor_type
                    entity_name = monitor_config.entity_name
                    if (not (context := self._registry.get_by_entity_name(monitor_type, entity_name)) 
                        or context.is_monitoring_stopped()):
                        self.logger.debug(f"Container {c.name} is not monitored yet. Starting monitoring.")
                        self._maybe_monitor_container(c, monitor_config=monitor_config)

            return self._start_message()
        except Exception as e:
            self.logger.error(f"Error handling config changes: {e}")
        return ""


    def _start_message(self):
        # Compose and log/send a summary message about monitored containers and services
        if self.hostname:
            message = f"[{self.hostname}]\n"
        else:
            message = ""
        if self.selected_containers:
            monitored_container_names = [c.entity_name for c in self._registry.get_actively_monitored(monitor_type=MonitorType.CONTAINER)]
            unmonitored_containers = [c for c in self.selected_containers if c not in monitored_container_names]
            message += generate_message(monitored_container_names, unmonitored_containers, "Containers")
        if self.selected_swarm_services: # self.swarm_mode:
            actively_monitored_swarm = [context for context in self._registry.get_actively_monitored(monitor_type=MonitorType.SWARM)]
            unmonitored_swarm_services = [s for s in self.selected_swarm_services if s not in [s.config_key for s in actively_monitored_swarm]]
            monitored_swarm_service_instances = [s.entity_name for s in actively_monitored_swarm]
            message += "\n\n" + generate_message(monitored_swarm_service_instances, unmonitored_swarm_services, "Swarm Services")
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
    

    def _start_monitoring_thread(self, container, container_context):
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
            error_count, last_error_time = 0, time.time()
            too_many_errors = False

            nonlocal container_context
            stop_monitoring_event = container_context.stop_monitoring_event
            monitoring_stopped_event = container_context.monitoring_stopped_event
            gen = container_context.generation  # get the generation of the current thread to check if a new thread is started for this container
            entity_name = container_context.entity_name
            processor = container_context.processor

            while not self.shutdown_event.is_set() and not stop_monitoring_event.is_set():
                buffer = b""
                not_found_error = False
                try:
                    now = datetime.now()
                    log_stream = container.logs(stream=True, follow=True, since=now)
                    container_context.log_stream = log_stream
                    monitoring_stopped_event.clear()
                    self.logger.info(f"Monitoring for Container started: {entity_name}")
                    for chunk in log_stream:
                        MAX_BUFFER_SIZE = 10 * 1024 * 1024  # 10MB
                        buffer += chunk
                        if len(buffer) > MAX_BUFFER_SIZE:
                            self.logger.error(f"{entity_name}: Buffer overflow detected for container, resetting")
                            buffer = b""
                        while b'\n' in buffer:
                            line, buffer = buffer.split(b'\n', 1)
                            try:
                                log_line_decoded = str(line.decode("utf-8")).strip()
                            except UnicodeDecodeError:
                                log_line_decoded = line.decode("utf-8", errors="replace").strip()
                                self.logger.warning(f"{entity_name}: Error while trying to decode a log line. Used errors='replace' for line: {log_line_decoded}")
                            if log_line_decoded:
                                processor.process_line(log_line_decoded)
                except docker.errors.NotFound as e:
                    self.logger.error(f"Container {entity_name} not found during Log Stream: {e}")
                    not_found_error = True
                except Exception as e:
                    error_count, last_error_time, too_many_errors = self._handle_error(error_count, last_error_time, entity_name)
                    if error_count == 1:  # log error only once
                        self.logger.error("Error trying to monitor %s: %s", entity_name, e)
                        self.logger.debug(traceback.format_exc())
                finally:
                    if self.shutdown_event.is_set():
                        break
                    if gen != container_context.generation:  # if there is a new thread running for this container this thread stops
                        self.logger.debug(f"{entity_name}: Stopping monitoring thread because a new thread was started for this container.")
                        break
                    elif too_many_errors or not_found_error or check_container(container_start_time, error_count) is False or stop_monitoring_event.is_set():
                        self._close_stream_connection(container.id)
                        break
                    else:
                        self.logger.info(f"{entity_name}: Log Stream stopped. Reconnecting... {'error count: ' + str(error_count) if error_count > 0 else ''}")
            self.logger.info(f"{entity_name}: Monitoring stopped for container.")
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
                            if container_context := self._registry.get_by_id(container_id):
                                self.logger.info(f"The Container {container_name or container_id} was stopped. Stopping Monitoring now.")
                                # if container_context.config_via_labels:
                                #     self.logger.debug(f"The Container {container_context.container_name} was stopped. Removing from config because it was configured via labels.")
                                #     remove_from_config(self.config, container_context.monitor_type, container_context.config_key)
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
        for context in self._registry.get_actively_monitored():
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

    def tail_logs(self, entity_name, monitor_type, lines=10):
        """
        Tail the last 'lines' of logs for a specific container.
        Returns the last 'lines' of logs as a list of strings.
        """
        if monitor_type and (container_context := self._registry.get_by_entity_name(monitor_type, entity_name)):
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
                self.logger.error(f"Container {entity_name} not found. Cannot tail logs.")
                return None
        else:
            self.logger.error(f"Container {entity_name} not found in registry. Cannot tail logs.\nMonitor Type: {monitor_type}\nself._registry {self._registry.get_actively_monitored(monitor_type='all')}")
            return None
        
    def container_action(self, entity_name, action, monitor_type=MonitorType.CONTAINER):
        """
        Perform an action on a container (start, stop, restart).
        """        
        if not (container_context := self._registry.get_by_entity_name(monitor_type, entity_name)):
            self.logger.error(f"Container {entity_name} not found in registry. Cannot perform action: {action}")
            return False
        container = self.client.containers.get(container_context.container_id)
        if container:
            try:
                container_name = container.name
                if action == ACTION_STOP:
                    self.logger.info(f"Stopping Container: {container_name}.")
                    container = container
                    container.stop()
                    if container.wait(timeout=10):
                        container.reload()
                        self.logger.debug(f"Container {container_name} has been stopped: Status: {container.status}")
                elif action == ACTION_RESTART:
                    self.logger.info(f"Restarting Container: {container_name}.")
                    container = container
                    container.restart()
                    container.reload()
                    self.logger.info(f"Container {container_name} has been restarted. Status: {container.status}")

            except Exception as e:
                self.logger.error(f"Failed to {action} {entity_name}: {e}")
                return False
        else:
            self.logger.error(f"Container {entity_name} not found. Could not perform action: {action}")
            return False




def get_service_entity_name(labels):
    """
    Tries to extract the service name with their replica id from container labels so that we have a unique name for each replica.
    """
    task_id = labels.get("com.docker.swarm.task.id")
    task_name = labels.get("com.docker.swarm.task.name")
    service_name = labels.get("com.docker.swarm.service.name", "")#
    stack_name = labels.get("com.docker.stack.namespace", "")
    if not any([service_name, task_id, task_name]):
        return None
    # Regex: service_name.<replica>.<task_id>
    pattern = re.escape(service_name) + r"\.(\d+)\." + re.escape(task_id) + r"$"
    regex = re.compile(pattern)
    match = regex.search(task_name)
    if match:
        return f"{service_name}.{match.group(1)}"
    else:
        return service_name or stack_name

def parse_label_config(labels: dict) -> dict:
    keywords_by_index = {}
    config = {}
    if labels.get("loggifly.monitor", "false").lower() != "true":
        return config
    logging.debug("Parsing loggifly monitor labels...")
    keywords_to_append = []
    for key, value in labels.items():
        if not key.startswith("loggifly."):
            continue
        parts = key[9:].split('.') 
        if len(parts) == 1:
            # Simple comma-separated keyword list
            if parts[0] == "keywords" and isinstance(value, str):
                keywords_to_append = [kw.strip() for kw in value.split(",") if kw.strip()]
            # Top Level Fields (e.g. ntfy_topic, attach_logfile, etc.)
            else:
                config[parts[0]] = value
        # Keywords
        elif parts[0] == "keywords":
            index = parts[1]
            # Simple keywords (direct value instead of dict)
            if len(parts) == 2:
                keywords_by_index[index] = value
            # Complex Keyword (Dict with fields)
            else:
                field = parts[2]
                if index not in keywords_by_index:
                    keywords_by_index[index] = {}
                keywords_by_index[index][field] = value
    
    config["keywords"] = [keywords_by_index[k] for k in sorted(keywords_by_index)]
    if keywords_to_append:
        config["keywords"].extend(keywords_to_append)
    logging.debug(f"Parsed config: {config}")
    return config

