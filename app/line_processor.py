import docker
import os
import re
import time
import json
from typing import Optional
import logging
import traceback
import threading
from threading import Thread, Lock
from notifier import send_notification
from services import perform_olivetin_action
from config.config_model import GlobalConfig, KeywordItem, RegexItem, KeywordGroup
from constants import (
    COMPILED_STRICT_PATTERNS, 
    COMPILED_FLEX_PATTERNS,
)

class LogProcessor:
    """
    Processes Docker container log lines to:
    - Detect and handle multi-line log entries using start patterns.
    - Search for keywords and regex patterns.
    - Trigger notifications and container actions (restart/stop) on matches.

    Pattern detection enables grouping of multi-line log entries 
    because every line that does not match the detected pattern is treated as part of the previous entry and added to the buffer.
    """
    # Use the pre-compiled patterns from constants.py
    COMPILED_STRICT_PATTERNS = COMPILED_STRICT_PATTERNS
    COMPILED_FLEX_PATTERNS = COMPILED_FLEX_PATTERNS

    def __init__(self,
                 logger, 
                 config: GlobalConfig, 
                 unit_config,
                 monitor_instance,
                 unit_name, 
                 monitor_type,
                 unit_stop_event,
                 hostname=None 
                 ):
        self.logger = logger
        self.hostname = hostname    # Hostname for multi-client setups to differentiate between clients; empty if single client
        self.unit_stop_event = unit_stop_event
        self.unit_name = unit_name
        self.monitor_type = monitor_type # container, swarm
        self.monitor_instance = monitor_instance # DockerMonitor instance from which the processor is called
        self.unit_config = unit_config

        self.patterns = []
        self.patterns_count = {pattern: 0 for pattern in self.__class__.COMPILED_STRICT_PATTERNS + self.__class__.COMPILED_FLEX_PATTERNS}
        self.lock_buffer = Lock()
        self.flush_thread_stopped = threading.Event()
        self.flush_thread_stopped.set()
        
        self.waiting_for_pattern = False
        self.valid_pattern = False
        self.line_count = 0
        self.line_limit = 300

        # These are updated in load_config_variables()
        self.multi_line_mode = False 
        self.time_per_keyword = {}
        self.time_per_action = {}

        self.load_config_variables(config, unit_config)
        # If multi-line mode is on, find starting pattern in logs
        if self.multi_line_mode is True:
            self.log_stream_last_updated = time.time()
            self.new_line_event = threading.Event()
            self.buffer = []
            if self.valid_pattern is False:
                log_tail = self.tail_logs(lines=100)
                if log_tail:
                    self._find_starting_pattern(log_tail)
                if self.valid_pattern:
                    self.logger.debug(f"{self.unit_name}: Mode: Multi-Line. Found starting pattern(s) in logs.")
                else:
                    self.logger.debug(f"{self.unit_name}: Mode: Single-Line. Could not find starting pattern in the logs. Continuing the search in the next {self.line_limit - self.line_count} lines")

    def _get_keywords(self, keywords):
        """
        Normalize and return a list of keyword/regex dicts from various input types. excluded_keywords come as a list of dicts.
        """
        returned_keywords = []
        for item in keywords:
            if isinstance(item, (KeywordItem)):
                self.logger.debug(f"Keyword item: {item}")
                returned_keywords.append((item.model_dump()))
            elif isinstance(item, RegexItem):
                self.logger.debug(f"Regex item: {item}")
                returned_keywords.append((item.model_dump()))
            elif isinstance(item, KeywordGroup):
                self.logger.debug(f"Keyword group: {item}")
                keyword_dict = item.model_dump()
                keyword_dict["keyword_group"] = tuple(keyword_dict["keyword_group"])
                self.logger.debug(f"Keyword dict: {keyword_dict}")
                returned_keywords.append(keyword_dict)
            elif isinstance(item, str):
                returned_keywords.append(({"keyword": item}))
            elif isinstance(item, dict) and "keyword_group" in item:
                item["keyword_group"] = tuple(item["keyword_group"])
                returned_keywords.append(item)
            elif isinstance(item, dict) and ("keyword" in item or "regex" in item):
                returned_keywords.append(item)
            else:
                self.logger.debug(f"Did not find correct item type for item: {item}")
        return returned_keywords

    def load_config_variables(self, config, unit_config):
        """
        Load and merge configuration for global and container-specific keywords and settings.
        Called on initialization and when reloading config.
        """
        self.config = config
        self.unit_config = unit_config
        self.time_per_keyword = {}
        unt_cnf = self.unit_config.model_dump() if self.unit_config else {}
        self.keywords = self._get_keywords(unt_cnf.get("keywords", []))
        self.keywords.extend(self._get_keywords(self.config.global_keywords.keywords))        

        self.container_msg_cnf = {
            "attachment_lines": unt_cnf.get("attachment_lines") or config.settings.attachment_lines,
            "notification_cooldown": unt_cnf.get("notification_cooldown") if unt_cnf.get("notification_cooldown") is not None else config.settings.notification_cooldown,
            "notification_title": unt_cnf.get("notification_title") or config.settings.notification_title,
            "attach_logfile": unt_cnf.get("attach_logfile") if unt_cnf.get("attach_logfile") is not None else config.settings.attach_logfile,
            "excluded_keywords": (unt_cnf.get("excluded_keywords") or []) + (config.settings.excluded_keywords or []),
            "hide_regex_in_title": unt_cnf.get("hide_regex_in_title") if unt_cnf.get("hide_regex_in_title") is not None else config.settings.hide_regex_in_title,
            "disable_notifications": unt_cnf.get("disable_notifications") or config.settings.disable_notifications or False,
            "action_cooldown": unt_cnf.get("action_cooldown") or config.settings.action_cooldown or 300,
        }
        self.multi_line_mode = config.settings.multi_line_entries
        # self.action_cooldown= unt_cnf.get("action_cooldown") or config.settings.action_cooldown or 300
        self.start_flush_thread_if_needed()


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
                self.logger.debug(f"{self.unit_name}: Found pattern: {pattern} with {count} matches of {self.line_count} lines. {round(count / self.line_count * 100, 2)}%")
                self.valid_pattern = True
                self.start_flush_thread_if_needed()
        if self.line_count >= self.line_limit:
            if self.patterns == []:
                self.logger.info(f"{self.unit_name}: No pattern found in logs after {self.line_limit} lines. Mode: single-line")

        self.waiting_for_pattern = False

    def get_message_config(self, keyword_message_config):
        """
        Merge container-level message config into keyword-level config for a single message.
        """
        for key, value in self.container_msg_cnf.items():
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
            if self.valid_pattern is True:
                self._process_multi_line(clean_line)
            else:
                self._search_and_send(clean_line)

    def start_flush_thread_if_needed(self):
        def check_flush():
            """
            Background thread: flushes buffer if timeout is reached or container stops.
            """
            self.logger.debug(f"Flush Thread started for {self.unit_name}.")
            self.flush_thread_stopped.clear()
            while not self.unit_stop_event.is_set():
                # Wait for new line event to be set but check every 60 seconds if the unit is stopped
                self.new_line_event.wait(60)
                if not self.new_line_event.is_set():
                    continue
                # Check if buffer needs to be flushed after one second passed since last log line
                while True:
                    time.sleep(1)
                    with self.lock_buffer:
                        if (time.time() - self.log_stream_last_updated > 1) or self.unit_stop_event.is_set():
                            if self.buffer:
                                self._handle_and_clear_buffer()
                                self.new_line_event.clear()
                            break
            self.flush_thread_stopped.set()
            self.logger.debug(f"Flush Thread stopped for {self.unit_name}")

        if not self.unit_stop_event.is_set() and self.multi_line_mode and self.valid_pattern and self.flush_thread_stopped.is_set():
            self.flush_thread = Thread(target=check_flush, daemon=True)
            self.flush_thread.start()

    def _handle_and_clear_buffer(self):
        """Flush buffer and process its contents as a single log entry."""
        log_entry = "\n".join(self.buffer)
        self.buffer.clear()
        if log_entry.strip():
            self._search_and_send(log_entry)
        else:
            self.logger.debug(f"Buffer for {self.unit_name} was empty, nothing to process.")

    def _process_multi_line(self, line):
        """
        In multi-line mode, determine if the line starts a new entry (pattern match).
        If so, flush buffer; otherwise, append line to buffer.
        """
        # Wait if pattern detection is in progress
        while self.waiting_for_pattern is True:
            time.sleep(1)
        # Check if the line matches any start pattern
        self.log_stream_last_updated = time.time()
        with self.lock_buffer:
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
        self.new_line_event.set()


    def _search_keyword(self, log_line, keyword_dict, ignore_keyword_time=False):
        """
        Search for keyword or regex in log_line. Enforce notification cooldown unless ignore_keyword_time is True.
        Returns the matched keyword/regex or None.
        """
        if keyword_dict.get("notification_cooldown"):
            notification_cooldown = keyword_dict["notification_cooldown"]
        else:
            notification_cooldown = self.container_msg_cnf.get("notification_cooldown", 10)
        log_line = log_line.lower()
        if "regex" in keyword_dict:
            regex = keyword_dict["regex"]
            if ignore_keyword_time or time.time() - self.time_per_keyword.get(regex, 0) >= int(notification_cooldown):
                match = re.search(regex, log_line, re.IGNORECASE)
                if match:
                    self.time_per_keyword[regex] = time.time()
                    hide_pattern = keyword_dict.get("hide_regex_in_title") if keyword_dict.get("hide_regex_in_title") else self.container_msg_cnf["hide_regex_in_title"]
                    return "Regex-Pattern" if hide_pattern else f"Regex: {regex}"
        elif "keyword" in keyword_dict:
            keyword = keyword_dict["keyword"]
            if ignore_keyword_time or time.time() - self.time_per_keyword.get(keyword, 0) >= int(notification_cooldown):
                if keyword.lower() in log_line:
                    self.time_per_keyword[keyword] = time.time()
                    return keyword
        elif "keyword_group" in keyword_dict:
            keyword_group = keyword_dict["keyword_group"]
            if ignore_keyword_time or time.time() - self.time_per_keyword.get(keyword_group, 0) >= int(notification_cooldown):
                if all(keyword.lower() in log_line for keyword in keyword_group):
                    self.time_per_keyword[keyword_group] = time.time()
                    return keyword_group
        return None

    def _search_and_send(self, log_line):
        """
        Search for keywords/regex in log_line and collect the keyword settings of all found keywords. 
        If a keyword is found, trigger notification and/or container action.
        """
        keywords_found = []
        excluded_keywords = []
        keyword_msg_cnf = {"message": log_line, "unit_name": self.unit_name, "monitor_type": self.monitor_type.value}
        template_found = False
        for keyword_dict in self.keywords:
            found = self._search_keyword(log_line, keyword_dict)
            if found:
                if template_found is False and keyword_dict.get("template") or keyword_dict.get("json_template"):
                    template_found = True
                    keyword_msg_cnf["message"] = message_from_template(keyword_dict, log_line)
                for key, value in keyword_dict.items():
                    if key == "excluded_keywords" and isinstance(value, list):
                        excluded_keywords.extend(value)
                    elif not keyword_msg_cnf.get(key) and value is not None:
                        keyword_msg_cnf[key] = value
                keywords_found.append(found)

        if not keywords_found:
            return
        # When an excluded keyword is found, the log line gets ignored and the function returns
        if exc := excluded_keywords + (self.container_msg_cnf.get("excluded_keywords") or []):
            for keyword in self._get_keywords(exc):
                found = self._search_keyword(log_line, keyword, ignore_keyword_time=True)
                if found:
                    self.logger.debug(f"Keyword(s) '{keywords_found}' found in '{self.unit_name}' but ignored because excluded keyword '{found}' was found")
                    return

        keyword_msg_cnf["keywords_found"] = keywords_found
        action_to_perform = keyword_msg_cnf.get("action")
        action_result = None
        if action_to_perform is not None:
            cooldown = self.container_msg_cnf["action_cooldown"]
            if self.time_per_action.get(action_to_perform, 0) < time.time() - int(cooldown):
                action_result = self._container_action(action_to_perform) # returns result as a string that can be used in a notification title
                self.time_per_action[action_to_perform] = time.time()
            else:
                last_action_time = time.strftime("%H:%M:%S", time.localtime(self.time_per_action.get(action_to_perform, 0)))
                self.logger.info(f"{self.unit_name}: Not performing action: '{action_to_perform}'. Action is on cooldown. Action was last performed at {last_action_time}. Cooldown is {cooldown} seconds.")

        msg_cnf = self.get_message_config(keyword_msg_cnf)
        attachment = None
        if msg_cnf["attach_logfile"]:
            if result := self._log_attachment(msg_cnf["attachment_lines"]):
                attachment = {"content": result[0], "file_name": result[1]}
            else:
                self.logger.error(f"Could not create log attachment file for Container {self.unit_name}")
            
        formatted_log_entry ="\n  -----  LOG-ENTRY  -----\n" + ' | ' + '\n | '.join(log_line.splitlines()) + "\n   -----------------------"
        self.logger.info(f"The following keywords were found in {self.unit_name}: {keywords_found}."
                    + (f" (A Log FIle will be attached)" if attachment else "")
                    + f"{formatted_log_entry}"
                    )
        disable_notifications = msg_cnf.get("disable_notifications") or self.container_msg_cnf.get("disable_notifications") or False
        if disable_notifications:
            self.logger.info(f"Not sending notification for {self.unit_name} because notifications are disabled.")

        if not disable_notifications:
            title = get_notification_title(msg_cnf, action_result)
            self._send_message(title, msg_cnf["message"], msg_cnf, attachment=attachment)

        if msg_cnf.get("olivetin_action_id"):
            title, message = perform_olivetin_action(self.config, msg_cnf, msg_cnf["olivetin_action_id"])
            if not disable_notifications:
                self._send_message(title, message, msg_cnf)

    def _send_message(self, title, message, msg_cnf, attachment=None):
        """
        Format notification title and call send_notification(). Optionally attach log file.
        """
        send_notification(self.config,
                        unit_name=self.unit_name,
                        title=title,
                        message=message,
                        message_config=msg_cnf,
                        unit_config=self.unit_config,
                        attachment=attachment,
                        hostname=self.hostname)

    def _log_attachment(self, number_attachment_lines):
        """
        Write the last N lines of container logs to a temporary file for notification attachment.
        Returns the file path or None on error.
        """
        file_name = f"last_{number_attachment_lines}_lines_from_{self.unit_name}.log"
        try:
            log_tail = self.tail_logs(lines=number_attachment_lines)
            if log_tail:
                return log_tail, file_name
        except Exception as e:
            self.logger.error(f"Could not create log attachment file for Container {self.unit_name}: {e}")
            return None, None

    def _container_action(self, action: str) -> Optional[str]:
        """
        Perform the specified container action (stop, start or restart). Returns result as a string that can be used in notification title.
        syntax is 'action' or 'action@container_name'
        """
        result = self.monitor_instance.container_action(self.monitor_type, self.unit_name, action)
        return result

    def tail_logs(self, lines=100):
        """
        Tail logs from the container. Calls the tail_logs method of the monitor instance.
        """
        return self.monitor_instance.tail_logs(unit_name=self.unit_name, 
                                                monitor_type=self.monitor_type, 
                                                lines=lines)

def get_notification_title(message_config: dict, action_result: Optional[str] = None):
    """
    Generate a notification title based on the template in the message config.
    """
    title = ""
    keywords_found = message_config.get("keywords_found", "")
    notification_title_config = message_config.get("notification_title", "default")
    unit_name = message_config.get("unit_name", "") 

    if notification_title_config.strip().lower() != "default":
        template = ""
        try:
            keywords = ', '.join(f"'{word}'" for word in keywords_found)
            template = notification_title_config.strip()
            template_fields = {
                "container": unit_name,
                "keywords": keywords, 
                "keyword": keywords, 
            }
            title = template.format(**template_fields)
        except KeyError as e:
            logging.error(f"Missing key in template: {template}. You can only put these keys in the template: 'container, keywords'. Error: {e}")
        except Exception as e:
            logging.error(f"Error trying to apply this template for the notification title: {template} {e}")

    if not title and isinstance(keywords_found, list):
        if len(keywords_found) == 1:
            keyword = keywords_found[0]
            title = f"'{keyword}' found in {unit_name}"
        elif len(keywords_found) == 2:
            joined_keywords = ' and '.join(f"'{word}'" for word in keywords_found)
            title = f"{joined_keywords} found in {unit_name}"
        elif len(keywords_found) > 2:
            joined_keywords = ', '.join(f"'{word}'" for word in keywords_found)
            title = f"The following keywords were found in {unit_name}: {joined_keywords}"

    if action_result is not None:
        title = f"{title} ({action_result})"

    if not title:
        title = f"{unit_name}: {keywords_found}"

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