import os
import logging
import copy
import yaml
import traceback
from .config_model import (
    GlobalConfig,
    SwarmServiceConfig,
    ContainerConfig,
    ValidationError,
    SecretStr
)
from constants import MonitorType

logging.getLogger(__name__)

"""
This module handles configuration loading and validation using Pydantic models. 
YAML configuration is loaded first, then environment variables are merged in, allowing environment variables to override YAML values, and YAML to override defaults. 
The merged configuration is validated with Pydantic. Legacy config formats are migrated for compatibility.
"""

def merge_yaml_and_env(yaml, env_update):
    """
    Recursively merge environment variable config into YAML config, overriding YAML values where present in env_update.
    """
    for key, value in env_update.items():
        if isinstance(value, dict) and key in yaml and key != {}:
            merge_yaml_and_env(yaml[key],value)
        else:
            if value is not None :
                yaml[key] = value
    return yaml


def load_config(official_path="/config/config.yaml"):
    """
    Load, merge, and validate the application configuration from YAML and environment variables.
    Returns the validated config object and the path used.
    """
    config_path = None
    required_keys = ["notifications", "settings", "global_keywords"]
    yaml_config = None
    legacy_path = "/app/config.yaml"
    paths = [official_path, legacy_path]
    for path in paths: 
        logging.debug(f"Trying path: {path}")
        if os.path.isfile(path):
            try:
                with open(path, "r") as file:
                    yaml_config = yaml.safe_load(file)
                    config_path = path
                    break
            except FileNotFoundError:
                logging.info(f"Error loading the config.yaml file from {path}")
            except yaml.YAMLError as e:
                logging.error(f"Error parsing the YAML file: {e}")
            except Exception as e:
                logging.error(f"Unexpected error loading the config.yaml file: {e}")
        else:
            logging.debug(f"The path {path} does not exist.")

    if yaml_config is None:
        logging.warning(f"The config.yaml could not be loaded.")
        yaml_config = {}
    else:
        logging.info(f"The config.yaml file was found in {config_path}.")

    for key in required_keys:
        if key not in yaml_config or yaml_config[key] is None:
            yaml_config[key] = {}

    """
    Load configuration values from environment variables, returning a config dict compatible with the YAML structure.
    """
    env_config = { "notifications": {}, "settings": {}, "global_keywords": {}}
    settings_values = {
        "log_level": os.getenv("LOG_LEVEL"),
        "attachment_lines": os.getenv("ATTACHMENT_LINES"),
        "multi_line_entries": os.getenv("MULTI_LINE_ENTRIES"),
        "notification_cooldown": os.getenv("NOTIFICATION_COOLDOWN"),
        "notification_title": os.getenv("NOTIFICATION_TITLE"),
        "reload_config": False if config_path is None else os.getenv("RELOAD_CONFIG"), 
        "disable_start_message": os.getenv("DISABLE_START_MESSAGE"),
        "disable_restart_message": os.getenv("DISABLE_CONFIG_RELOAD_MESSAGE"),
        "disable_shutdown_message": os.getenv("DISABLE_SHUTDOWN_MESSAGE"),
        "disable_container_event_message": os.getenv("DISABLE_CONTAINER_EVENT_MESSAGE"),
        "action_cooldown": os.getenv("ACTION_COOLDOWN"),
        "attach_logfile": os.getenv("ATTACH_LOGFILE", "false").lower() == "true",
        "hide_regex_in_title": os.getenv("HIDE_REGEX_IN_TITLE", "false").lower() == "true",
        "disable_notifications": os.getenv("DISABLE_NOTIFICATIONS", "false").lower() == "true",
        "excluded_keywords": [kw.strip() for kw in os.getenv("EXCLUDED_KEYWORDS", "").split(",") if kw.strip()] if os.getenv("EXCLUDED_KEYWORDS") else None,
        "olivetin_url": os.getenv("OLIVETIN_URL"),
        "olivetin_username": os.getenv("OLIVETIN_USERNAME"),
        "olivetin_password": os.getenv("OLIVETIN_PASSWORD"),
        } 
    ntfy_values =  {
        "url": os.getenv("NTFY_URL"),
        "topic": os.getenv("NTFY_TOPIC"),
        "token": os.getenv("NTFY_TOKEN"),
        "priority": os.getenv("NTFY_PRIORITY"),
        "tags": os.getenv("NTFY_TAGS"),
        "username": os.getenv("NTFY_USERNAME"),
        "password": os.getenv("NTFY_PASSWORD")
        }
    webhook_values = {
        "url": os.getenv("WEBHOOK_URL"),
        "headers":os.getenv("WEBHOOK_HEADERS")
    }
    apprise_values = {
        "url": os.getenv("APPRISE_URL")
    }
    global_keywords_values = {
        "keywords": [kw.strip() for kw in os.getenv("GLOBAL_KEYWORDS", "").split(",") if kw.strip()] if os.getenv("GLOBAL_KEYWORDS") else [],
        "keywords_with_attachment": [kw.strip() for kw in os.getenv("GLOBAL_KEYWORDS_WITH_ATTACHMENT", "").split(",") if kw.strip()] if os.getenv("GLOBAL_KEYWORDS_WITH_ATTACHMENT") else [],
    }
    # Fill env_config dict with environment variables if they are set
    if os.getenv("CONTAINERS"):
        env_config["containers"] = {}
        for c in os.getenv("CONTAINERS", "").split(","):
            c = c.strip()
            env_config["containers"][c] = {}

    if os.getenv("SWARM_SERVICES"):
        env_config["swarm_services"] = {}
        for s in os.getenv("SWARM_SERVICES", "").split(","):
            s = s.strip()
            env_config["swarm_services"][s] = {}

    if any(ntfy_values.values()):
        env_config["notifications"]["ntfy"] = ntfy_values
        yaml_config["notifications"]["ntfy"] = {} if yaml_config["notifications"].get("ntfy") is None else yaml_config["notifications"]["ntfy"]

    if apprise_values["url"]: 
        env_config["notifications"]["apprise"] = apprise_values

    if webhook_values.get("url"):
        env_config["notifications"]["webhook"] = webhook_values
        yaml_config["notifications"]["webhook"] = {} if yaml_config["notifications"].get("webhook") is None else yaml_config["notifications"]["webhook"]

    for k, v in global_keywords_values.items():
        if v:
            env_config["global_keywords"][k]= v

    for key, value in settings_values.items(): 
        if value is not None:
            env_config["settings"][key] = value

    # Merge environment variables and yaml config
    merged_config = merge_yaml_and_env(yaml_config, env_config)
    merged_config = convert_legacy_formats(merged_config)
    # Validate the merged configuration with Pydantic
    config = GlobalConfig.model_validate(merged_config)
    yaml_output = get_pretty_yaml_config(config)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path

def validate_unit_config(monitor_type, config_dict):
    try:
        if monitor_type == MonitorType.SWARM:
            return SwarmServiceConfig.model_validate(config_dict)
        elif monitor_type == MonitorType.CONTAINER:
            return ContainerConfig.model_validate(config_dict)
    except ValidationError as e:
        type_str = monitor_type.value if hasattr(monitor_type, "value") else monitor_type
        logging.error(f"Error validating {type_str} config: {e}")
        return None
    except Exception as e:
        type_str = monitor_type.value if hasattr(monitor_type, "value") else monitor_type
        logging.error(f"Unexpected error validating {type_str} config: {e}")
        return None

def get_pretty_yaml_config(config, top_level_key=None):
    config_dict = prettify_config_dict(config.model_dump(
        exclude_none=True, 
        exclude_defaults=False, 
        exclude_unset=False,
    ))
    if top_level_key:
        config_dict = {top_level_key: config_dict}
    return yaml.dump(config_dict, default_flow_style=False, sort_keys=False, indent=4)

def prettify_config_dict(data):
    """Recursively format config dict for display, masking secrets and ordering keys for readability."""
    if isinstance(data, dict):
        priority_keys = [k for k in ("regex", "keyword") if k in data]
        if priority_keys:
            rest_keys = [k for k in data.keys() if k not in priority_keys]
            ordered_dict = {k: data[k] for k in priority_keys + rest_keys}
            return {k: prettify_config_dict(v) for k, v in ordered_dict.items()}
        return {k: prettify_config_dict(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [prettify_config_dict(item) for item in data]
    elif isinstance(data, SecretStr):
        return "**********"  
    else:
        return data

def convert_legacy_formats(config):
    """
    Migrate legacy configuration fields (e.g., keywords_with_attachment, action_keywords) to the current format.
    """
    def _migrate_keywords(legacy, new, new_field):
        new_key, new_value = new_field
        for item in legacy:
            if isinstance(item, (str, int)):
                new.append({"keyword": str(item), new_key: new_value})
            elif isinstance(item, dict):
                item[new_key] = new_value
                new.append(item)
    
    config_copy = copy.deepcopy(config)
    global_kw = config_copy.get("global_keywords", {})
    global_with_attachment = global_kw.pop("keywords_with_attachment", None)
    if global_with_attachment is not None:
        config_copy["global_keywords"].setdefault("keywords", [])
        _migrate_keywords(global_with_attachment, config_copy["global_keywords"]["keywords"], ("attach_logfile", True))
    
    for container_object in ["containers", "swarm_services"]:
        if container_object not in config_copy:
            continue
        for container_config in config_copy.get(container_object, {}).values():
            if container_config is None:
                continue
            container_config.setdefault("keywords", [])
            keywords_with_attachment = container_config.pop("keywords_with_attachment", None)
            if keywords_with_attachment is not None:
                _migrate_keywords(keywords_with_attachment, container_config["keywords"], ("attach_logfile", True))
            
            action_keywords = container_config.pop("action_keywords", None)
            if action_keywords is not None:
                for item in action_keywords:
                    if isinstance(item, dict):
                        if "restart" in item:
                            action = "restart"
                        elif "stop" in item:
                            action = "stop"
                        else:
                            action = None 
                        if action:
                            keyword = item[action]
                            if isinstance(keyword, dict) and "regex" in keyword:
                                container_config["keywords"].append({"regex": keyword["regex"], "action": action})
                            elif isinstance(keyword, str):
                                container_config["keywords"].append({"keyword": keyword, "action": action})
    return config_copy

def format_pydantic_error(e: ValidationError) -> str:
    """Format Pydantic validation errors for user-friendly display."""
    error_messages = []
    for error in e.errors():
        location = ".".join(map(str, error["loc"]))
        msg = error["msg"]
        msg = msg.split("[")[0].strip()
        error_messages.append(f"Field '{location}': {msg}")
    return "\n".join(error_messages)