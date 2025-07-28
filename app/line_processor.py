import docker
import os
import re
import time
import json
import string
import logging
import traceback
import threading
from threading import Thread, Lock
from notifier import send_notification
from pydantic import SecretStr
from load_config import GlobalConfig, KeywordItem, RegexItem
# from docker_monitor import DockerLogMonitor

class LogProcessor:
    """
    Processes Docker container log lines to:
    - Detect and handle multi-line log entries using start patterns.
    - Search for keywords and regex patterns.
    - Trigger notifications and container actions (restart/stop) on matches.

    Pattern detection enables grouping of multi-line log entries 
    because every line that does not match the detected pattern is treated as part of the previous entry and added to the buffer.
    """
    STRICT_PATTERNS = [
        # Timestamp and log level at line start
        r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d{3})?\] \[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]", # 
        r"^\d{4}-\d{2}-\d{2}(?:, | )\d{2}:\d{2}:\d{2}(?:,\d{3})? (?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)",

        # ISO timestamp in brackets
        r"^\[\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\]", # [2025-02-17T03:23:07Z] or [2025-02-17 04:22:59 +0100] or [2025-02-18T03:23:05.436627]

        # Month in brackets
        r"^\[(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\]",                                                  # [Feb 17, 2025 10:13:02]
        r"^\[\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\]", # [17/Feb/2025:10:13:02 +0000]

        # ISO timestamp without brackets
        r"^\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b",

        # Month without brackets
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4} \d{2}:\d{2}:\d{2}\b",
        r"\b\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}(?:\:| |\/)\d{2}:\d{2}:\d{2}(?:Z||\s[+\-]\d{2}:\d{2}|\s[+\-]\d{4})\b",   # 17/Feb/2025:10:13:02 +0000
        
        # Unix-like timestamps
        r"^\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{2,6}\]",
        
        # Log level at line start
        r"^\[(?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\]",
        r"^\((?:INFO|ERROR|DEBUG|WARN|WARNING|CRITICAL)\)"
    ]
    FLEX_PATTERNS = [
        # Generic timestamps (fallback)
        r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b",
        r"\b\d{4}-\d{2}-\d{2}(?:T|, | )\d{2}:\d{2}:\d{2}(?:Z|[\.,]\d{2,6}|[+-]\d{2}:\d{2}| [+-]\d{4})\b", # 2025-02-17T03:23:07Z
        r"\b(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])-\d{4} \d{2}:\d{2}:\d{2}\b",
        r"(?i)\b\d{2}\/\d{2}\/\d{4}(?:,\s+|:|\s+])\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?\b",
        r"\b\d{10}\.\d+\b",                                                          # 1739762586.0394847
        # Log level (fallback)
        r"(?i)(?<=^)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",      
        r"(?i)(?<=\s)\b(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\b(?=\s|:|$)",
        r"(?i)\[(?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\]",
        r"(?i)\((?:INFO|ERROR|DEBUG|WARN(?:ING)?|CRITICAL)\)",
        r"(?i)\d{2}/\d{2}/\d{4},\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)",
    ]

    COMPILED_STRICT_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in STRICT_PATTERNS]
    COMPILED_FLEX_PATTERNS = [re.compile(pattern, re.ASCII) for pattern in FLEX_PATTERNS]

    def __init__(self,
                 logger, 
                 config: GlobalConfig, 
                 monitor_instance,
                 monitored_object_name, 
                 monitor_type,
                 hostname=None, 
                 container_stop_event=None, 
                 config_key=None,
                 ):
        self.logger = logger
        self.hostname = hostname    # Hostname for multi-client setups; empty if single client
        self.container_stop_event = container_stop_event
        self.monitored_object_name = monitored_object_name
        self.monitor_type = monitor_type
        self.monitor_instance = monitor_instance    
        self.config_key = config_key if config_key else monitored_object_name

        self.patterns = []
        self.patterns_count = {pattern: 0 for pattern in self.__class__.COMPILED_STRICT_PATTERNS + self.__class__.COMPILED_FLEX_PATTERNS}
        self.lock_buffer = Lock()
        self.flush_thread_stopped = threading.Event()
        self.flush_thread_stopped.set()
        self.waiting_for_pattern = False
        self.valid_pattern = False

        self.load_config_variables(config)

    def _get_keywords(self, keywords):
        """
        Normalize and return a list of keyword/regex dicts from various input types. excluded_keywords come as a list of dicts.
        """
        returned_keywords = []
        for item in keywords:
            if isinstance(item, (KeywordItem)):
                returned_keywords.append((item.model_dump()))
            elif isinstance(item, RegexItem):
                returned_keywords.append((item.model_dump()))
            elif isinstance(item, str):
                returned_keywords.append(({"keyword": item}))
            elif isinstance(item, dict) and ("keyword" in item or "regex" in item):
                returned_keywords.append(item)
        return returned_keywords

    def load_config_variables(self, config):
        """
        Load and merge configuration for global and container-specific keywords and settings.
        Called on initialization and when reloading config.
        """
        self.config = config
        config_global_keywords = self.config.global_keywords
        self.keywords = self._get_keywords(config_global_keywords.keywords)
        

        if self.monitor_type == "swarm":
            self.container_config = self.config.swarm_services.get(self.config_key)
        elif self.monitor_type == "systemd":
            self.container_config = self.config.systemd_services.get(self.config_key)
        elif self.monitor_type == "container":
            self.container_config = self.config.containers.get(self.config_key)

        self.keywords.extend(self._get_keywords(self.container_config.keywords))

        self.container_message_config = {
            "attachment_lines": self.container_config.attachment_lines or self.config.settings.attachment_lines,
            "notification_cooldown": self.container_config.notification_cooldown or self.config.settings.notification_cooldown,
            "notification_title": self.container_config.notification_title or self.config.settings.notification_title,
            "attach_logfile": self.container_config.attach_logfile if self.container_config.attach_logfile is not None else self.config.settings.attach_logfile,
            "excluded_keywords": self.container_config.excluded_keywords or self.config.settings.excluded_keywords,
            "hide_regex_in_title": self.container_config.hide_regex_in_title if self.container_config.hide_regex_in_title is not None else self.config.settings.hide_regex_in_title,
        }

        self.multi_line_mode = False if self.monitor_type == "systemd" else self.config.settings.multi_line_entries
        self.action_cooldown= self.container_config.action_cooldown or self.config.settings.action_cooldown or 300
        self.time_per_keyword = {}
        self.last_action_time = None
        for keyword_dict in self.keywords:
            keyword = keyword_dict.get("keyword") or keyword_dict.get("regex")
            self.time_per_keyword[keyword] = 0

        if self.multi_line_mode is True and not self.monitor_type == "systemd":
            self.line_count = 0
            self.line_limit = 300
            if self.valid_pattern is False:
                log_tail = self.monitor_instance.tail_logs(monitored_object_name=self.monitored_object_name, 
                                                            monitor_type=self.monitor_type, 
                                                            lines=100)
                if log_tail:
                    self._find_starting_pattern(log_tail)
                if self.valid_pattern:
                    self.logger.debug(f"{self.monitored_object_name}: Mode: Multi-Line. Found starting pattern(s) in logs.")
                else:
                    self.logger.debug(f"{self.monitored_object_name}: Mode: Single-Line. Could not find starting pattern in the logs. Continuing the search in the next {self.line_limit - self.line_count} lines")

            self.buffer = []
            self.log_stream_timeout = 1 # Not yet configurable
            self.log_stream_last_updated = time.time()
            # Start background thread for buffer flushing
            self._start_flush_thread()

    def get_message_config(self, keyword_message_config):
        """
        Merge container-level message config into keyword-level config for a single message.
        """
        for key, value in self.container_message_config.items():
            if key not in keyword_message_config:
                keyword_message_config[key] = value
            elif isinstance(value, list) and isinstance(keyword_message_config.get(key), list):
                keyword_message_config[key].extend(value)
        return keyword_message_config

    def process_line(self, line):
        """        
        Entry point for processing a single log line. 
        If multi-line mode is off or no pattern is detected, processes as single line; otherwise, processes as part of a multi-line entry.
        """
        clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        if self.multi_line_mode is False:
            self._search_and_send(clean_line)
        else:
            if self.line_count < self.line_limit:
                self._find_starting_pattern(clean_line)
            if self.valid_pattern == True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_send(clean_line)

    def _find_starting_pattern(self, log):
        """
        Analyze log lines to identify patterns that mark the beginning of new log entries.
        If a pattern is detected frequently enough, it is added to self.patterns and self.valid_pattern is set to True, enabling multi-line log entry grouping.
        If no pattern is found after scanning, self.valid_pattern remains False and the processor falls back to single-line mode (treating each line as a separate entry).
        """
        self.waiting_for_pattern = True
        for line in log.splitlines():
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            self.line_count += 1
            for pattern in self.__class__.COMPILED_STRICT_PATTERNS:
                if pattern.search(clean_line):
                    self.patterns_count[pattern] += 1
                    break
            else:
                for pattern in self.__class__.COMPILED_FLEX_PATTERNS:
                    if pattern.search(clean_line):
                        self.patterns_count[pattern] += 1
                        break

        sorted_patterns = sorted(self.patterns_count.items(), key=lambda x: x[1], reverse=True)
        threshold = max(5, int(self.line_count * 0.075))

        for pattern, count in sorted_patterns:
            if pattern not in self.patterns and count > threshold:
                self.patterns.append(pattern)
                self.logger.debug(f"{self.monitored_object_name}: Found pattern: {pattern} with {count} matches of {self.line_count} lines. {round(count / self.line_count * 100, 2)}%")
                self.valid_pattern = True
        if self.patterns == []:
            self.valid_pattern = False
        if self.line_count >= self.line_limit:
            if self.patterns == []:
                self.logger.info(f"{self.monitored_object_name}: No pattern found in logs after {self.line_limit} lines. Mode: single-line")

        self.waiting_for_pattern = False

    def _start_flush_thread(self):
        def check_flush():
            """
            Background thread: flushes buffer if timeout is reached or container stops.
            """
            self.flush_thread_stopped.clear()
            while True:
                if self.container_stop_event and self.container_stop_event.is_set():
                    time.sleep(4)
                    if self.container_stop_event.is_set():
                        break
                if self.multi_line_mode is False:
                    break
                with self.lock_buffer:
                    if (time.time() - self.log_stream_last_updated > self.log_stream_timeout) and self.buffer:
                        self._handle_and_clear_buffer()
                time.sleep(1)
            self.flush_thread_stopped.set()
            self.logger.debug(f"Flush Thread stopped for Container {self.monitored_object_name}")

        if self.monitor_type != "systemd" and self.flush_thread_stopped.is_set():
            self.flush_thread = Thread(target=check_flush, daemon=True)
            self.flush_thread.start()

    def _handle_and_clear_buffer(self):
        """Flush buffer and process its contents as a single log entry."""
        log_entry = "\n".join(self.buffer)
        self._search_and_send(log_entry)
        self.buffer.clear()

    def _process_multi_line(self, line):
        """
        In multi-line mode, determine if the line starts a new entry (pattern match).
        If so, flush buffer; otherwise, append line to buffer.
        """
        # Wait if pattern detection is in progress
        while self.waiting_for_pattern is True:
            time.sleep(1)

        for pattern in self.patterns:
            # If line matches a start pattern, flush buffer and start new entry
            if pattern.search(line):
                if self.buffer:
                    self._handle_and_clear_buffer()
                self.buffer.append(line)
                break
        # Otherwise, append to current buffer (continuation of previous entry)
        else:
            if self.buffer:
                self.buffer.append(line)
            else:
                # Fallback: unexpected format, start new buffer
                self.buffer.append(line)
        self.log_stream_last_updated = time.time()

    def _search_keyword(self, log_line, keyword_dict, ignore_keyword_time=False):
        """
        Search for keyword or regex in log_line. Enforce notification cooldown unless ignore_keyword_time is True.
        Returns the matched keyword/regex or None.
        """
        notification_cooldown = keyword_dict.get("notification_cooldown") if keyword_dict.get("notification_cooldown") else self.container_message_config["notification_cooldown"]
        if "regex" in keyword_dict:
            regex = keyword_dict.get("regex")
            if ignore_keyword_time or time.time() - self.time_per_keyword.get(regex, 0) >= int(notification_cooldown):
                match = re.search(regex, log_line, re.IGNORECASE)
                if match:
                    self.time_per_keyword[regex] = time.time()
                    hide_pattern = keyword_dict.get("hide_regex_in_title") if keyword_dict.get("hide_regex_in_title") else self.container_message_config["hide_regex_in_title"]
                    return "Regex-Pattern" if hide_pattern else f"Regex: {regex}"
        else:
            keyyword = keyword_dict.get("keyword")
            if ignore_keyword_time or time.time() - self.time_per_keyword.get(keyyword, 0) >= int(notification_cooldown):
                if keyyword.lower() in log_line.lower():
                    self.time_per_keyword[keyyword] = time.time()
                    return keyyword
        return None

    def _search_and_send(self, log_line):
        """
        Search for keywords/regex in log_line and collect the keyword settings of all found keywords. 
        If a keyword is found, trigger notification and/or container action.
        """
        keywords_found = []
        excluded_keywords = self.container_config.excluded_keywords if self.container_config.excluded_keywords else []
        keyword_message_config = {"message": log_line, "monitored_object_name": self.monitored_object_name, "monitor_type": self.monitor_type}
        template_found = False
        for keyword_dict in self.keywords:
            found = self._search_keyword(log_line, keyword_dict)
            if found:
                if template_found is False and keyword_dict.get("template") or keyword_dict.get("json_template"):
                    template_found = True
                    keyword_message_config["message"] = message_from_template(keyword_dict, log_line)
                if keyword_dict.get("excluded_keywords"):
                    excluded_keywords.extend(keyword_dict["excluded_keywords"])
                for key, value in keyword_dict.items():
                    if not keyword_message_config.get(key) and value is not None:
                        keyword_message_config[key] = value
                keywords_found.append(found)

        # Send notification if any keywords matched
        if keywords_found:
            # when a excluded keyword is found, the log line gets ignored and the function returns
            if excluded_keywords:
                for keyword in self._get_keywords(excluded_keywords):
                    found = self._search_keyword(log_line, keyword, ignore_keyword_time=True)
                    if found:
                        self.logger.debug(f"Keyword(s) '{keywords_found}' found in '{self.monitored_object_name} but IGNORED because excluded keyword '{found}' was found")
                        return

            keyword_message_config["keywords_found"] = keywords_found
            action = keyword_message_config.get("action")
            if self.monitor_type == "container" and action is not None:
                if self.last_action_time is None or (self.last_action_time is not None and time.time() - self.last_action_time >= max(int(self.action_cooldown), 60)):
                    success = self._container_action(action)
                    action = (action, success)
                    self.last_action_time = time.time()
                else:
                    action = None
            else:
                action = None

            message_config = self.get_message_config(keyword_message_config)
            attach_logfile = message_config["attach_logfile"]
            formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
            self.logger.info(f"The following keywords were found in {self.monitored_object_name}: {keywords_found}."
                        + (f" (A Log FIle will be attached)" if attach_logfile else "")
                        + f"{formatted_log_entry}"
                        )
            self._send_message(message_config, attach_logfile=attach_logfile, action=action)

    def _send_message(self, message_config, attach_logfile=False, action=None):
        """
        Format notification title and call send_notification(). Optionally attach log file.
        """
        title = get_notification_title(message_config, action)
        file_path = None
        if attach_logfile:
            file_path = self._log_attachment(message_config["attachment_lines"])
            message_config["file_path"] = file_path
        send_notification(self.config,
                          monitored_object_name=self.monitored_object_name,
                          title=title,
                          message=message_config["message"],
                          message_config=message_config,
                          container_config=self.container_config,
                          hostname=self.hostname)

        if file_path and isinstance(file_path, str):
            if os.path.exists(file_path):
                os.remove(file_path)
                self.logger.debug(f"The file {file_path} was deleted.")
            else:
                self.logger.debug(f"The file {file_path} does not exist.")

    def _log_attachment(self, number_attachment_lines):
        """
        Write the last N lines of container logs to a temporary file for notification attachment.
        Returns the file path or None on error.
        """
        base_name = f"last_{number_attachment_lines}_lines_from_{self.monitored_object_name}.log"
        folder = "/tmp/"

        def find_available_name(filename, number=1):
            """
            Generate a unique file name if a file with the base name already exists in case of many notifications at same time.
            """
            new_name = f"{filename.rsplit('.', 1)[0]}_{number}.log"
            path = folder + new_name
            if os.path.exists(path):
                return find_available_name(filename, number + 1)
            return path
    
        if os.path.exists(base_name):
            file_path = find_available_name(base_name)
        else:
            file_path = folder + base_name
        try:
            os.makedirs("/tmp", exist_ok=True)
            log_tail = self.monitor_instance.tail_logs(monitored_object_name=self.monitored_object_name, 
                                                       monitor_type=self.monitor_type, 
                                                       lines=number_attachment_lines)
            if log_tail:
                with open(file_path, "w") as file:
                    file.write(log_tail)
                    logging.debug(f"Wrote file: {file_path}")
                    return file_path
        except Exception as e:
            self.logger.error(f"Could not create log attachment file for Container {self.monitored_object_name}: {e}")
            return None

    def _container_action(self, action):
        """
        Perform the specified container action (stop or restart). Returns True on success, False on error.
        """
        if self.monitor_type == "container":
            result = self.monitor_instance.container_action(self.monitored_object_name, action)
            return result
        else:
            self.logger.debug(f"Skipping container action for {self.monitored_object_name} because it is a swarm service or not a docker container.")
            return False


def get_notification_title(message_config, action):
    """
    Generate a notification title based on the template in the message config.
    """
    title = ""
    keywords_found = message_config.get("keywords_found", "")
    notification_title = message_config.get("notification_title", "default")
    monitored_object_name = message_config.get("monitored_object_name", "") 

    if notification_title.strip().lower() != "default":
        template = ""
        try:
            keywords = ', '.join(f"'{word}'" for word in keywords_found)
            template = notification_title.strip()
            template_fields = {"container": monitored_object_name, 
                               "keywords": keywords, 
                               "keyword": keywords, 
                               "systemd_service": monitored_object_name, 
                               "swarm_service": monitored_object_name
                               }
            title = template.format(**template_fields)
        except KeyError as e:
            logging.error(f"Missing key in template: {template}. You can only put these keys in the template: 'container, keywords'. Error: {e}")
        except Exception as e:
            logging.error(f"Error trying to apply this template for the notification title: {template} {e}")

    if not title and isinstance(keywords_found, list):
        if len(keywords_found) == 1:
            keyword = keywords_found[0]
            title = f"'{keyword}' found in {monitored_object_name}"
        elif len(keywords_found) == 2:
            joined_keywords = ' and '.join(f"'{word}'" for word in keywords_found)
            title = f"{joined_keywords} found in {monitored_object_name}"
        elif len(keywords_found) > 2:
            joined_keywords = ', '.join(f"'{word}'" for word in keywords_found)
            title = f"The following keywords were found in {monitored_object_name}: {joined_keywords}"

    if action and not title:
        action, success = action
        if success:
            title = f"{monitored_object_name} was {'stopped' if action == 'stop' else 'restarted'}! - " + title
        else:
            title = f"Failed to {'stop' if action == 'stop' else 'restart'} {monitored_object_name}!" + title

    if not title:
        title = f"{monitored_object_name}: {keywords_found}"

    return title


def message_from_template(keyword_dict, log_line):
    """
    Format a message using a template:
    - For 'json_template', parse the log line as JSON and fill the template with its fields.
    - For 'template' with 'regex', use named capturing groups from the regex to fill the template.
    'original_log_line' is always available in the template context.
    """
    message = log_line

    if keyword_dict.get("json_template"):
        template = keyword_dict.get("json_template")
        try:
            json_log_entry = json.loads(log_line)
            json_log_entry["original_log_line"] = log_line  # Add original log line to JSON data
            logging.debug(f"TEMPLATE: {template}")
            message = template.format(**json_log_entry)
            logging.debug(f"Successfully applied this template: {template}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            logging.error(f"Error parsing log line as JSON: {log_line}")
        except KeyError as e:
            logging.error(f"KeyError: {e} in template: {template} with log line: {log_line}")
            logging.debug(f"Traceback: {traceback.format_exc()}")
        except Exception as e:
            logging.error(f"Unexpected Error trying to parse a JSON log line with template {template}: {e}")
            logging.error(f"Details: {traceback.format_exc()}")
    elif keyword_dict.get("regex") and keyword_dict.get("template"):
        template = keyword_dict.get("template")
        match = re.search(keyword_dict["regex"], log_line, re.IGNORECASE)
        if match:
            groups = match.groupdict()
            groups.setdefault("original_log_line", log_line)
            try:
                message = template.format(**groups)
                logging.debug(f"Successfully applied this template: {template}")
                return message
            except KeyError as e:
                logging.error(f"Key Error for template '{template}': {e}")
            except Exception as e:
                logging.error(f"Error applying template {template}: {e}")
    return message