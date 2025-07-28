from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    ValidationError
)
from enum import Enum
from typing import List, Optional, Union, ClassVar
import os
import logging
import copy
import yaml

logging.getLogger(__name__)

"""
This module handles configuration loading and validation using Pydantic models. 
YAML configuration is loaded first, then environment variables are merged in, allowing environment variables to override YAML values, and YAML to override defaults. 
The merged configuration is validated with Pydantic. Legacy config formats are migrated for compatibility.
"""

def validate_priority(v):
    """
    Validate and normalize the priority value for notifications. Accepts both string and integer representations.
    Returns a valid priority or the default if invalid.
    """
    if isinstance(v, str):
        try:
            v = int(v)
        except ValueError:
            pass
    if isinstance(v, int):
        if not 1 <= int(v) <= 5:
            logging.warning(f"Error in config for ntfy.priority. Must be between 1-5, '{v}' is not allowed. Using default: '3'")
            return 3
    if isinstance(v, str):
        options = ["max", "urgent", "high", "default", "low", "min"]
        if v not in options:
            logging.warning(f"Error in config for ntfy.priority:'{v}'. Only 'max', 'urgent', 'high', 'default', 'low', 'min' are allowed. Using default: '3'")
            return 3
    return v

class BaseConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        validate_default=True,
        use_enum_values=True,
        from_attributes=False,
        arbitrary_types_allowed=False,
    )

class ExcludedKeywords(BaseConfigModel):
    keyword: Optional[str] = None
    regex: Optional[str] = None

class Settings(BaseConfigModel):    
    """
    Application-wide settings for logging, notifications, and feature toggles.
    """
    log_level: str = "INFO"
    multi_line_entries: bool = True
    disable_start_message: bool = False
    disable_shutdown_message: bool = False
    disable_config_reload_message: bool = False
    disable_container_event_message: bool = False
    reload_config: bool = True
    
    # modular settings:
    attach_logfile: bool = False
    notification_cooldown: int = 5
    notification_title: str = "default"
    action_cooldown: Optional[int] = 300
    attachment_lines: int = 20
    hide_regex_in_title: Optional[bool] = False
    excluded_keywords: Optional[List[Union[str, ExcludedKeywords]]] = None
    
class ModularSettings(BaseConfigModel):
    """
    Optional settings that can be overridden per keyword or container.
    """
    ntfy_tags: Optional[str] = None
    ntfy_topic: Optional[str] = None
    ntfy_priority: Optional[Union[str, int]] = None
    ntfy_url: Optional[str] = None
    ntfy_token: Optional[SecretStr] = None
    ntfy_username: Optional[str] = None
    ntfy_password: Optional[SecretStr] = None
    apprise_url: Optional[SecretStr] = None
    webhook_url: Optional[str] = None
    webhook_headers: Optional[dict] = None

    attachment_lines: Optional[int] = None
    notification_cooldown: Optional[int] = None
    notification_title: Optional[str] = None
    action_cooldown: Optional[int] = None
    attach_logfile: Optional[bool] = None
    excluded_keywords: Optional[List[Union[str, ExcludedKeywords]]] = None
    hide_regex_in_title: Optional[bool] = None

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)

class ActionEnum(str, Enum):
    RESTART = "restart"
    STOP = "stop"



class RegexItem(ModularSettings):
    """
    Model for a regex-based keyword with optional settings.
    """
    regex: str
    json_template: Optional[str] = None
    template: Optional[str] = None
    action: Optional[ActionEnum] = None

class KeywordItem(ModularSettings):
    """
    Model for a string-based keyword with optional settings.
    """
    keyword: str
    json_template: Optional[str] = None
    action: Optional[ActionEnum] = None

class KeywordBase(BaseModel):
    """
    Base model for keyword lists, with pre-validation to handle legacy and misconfigured entries.
    """
    _DISALLOW_ACTION: ClassVar[bool] = False

    keywords: List[Union[str, KeywordItem, RegexItem]] = []

    @model_validator(mode="before")
    def int_to_string(cls, data: dict) -> dict:
        """
        Convert integer keywords to strings and filter out misconfigured entries before validation.
        """
        if "keywords" in data and isinstance(data["keywords"], list):
            converted = []
            for item in data["keywords"]:
                if isinstance(item, dict):
                    keys = list(item.keys())
                    if "keyword" not in item and "regex" not in item:
                        logging.warning(f"Ignoring Error in config in field 'keywords': '{item}'. You have to set 'keyword' or 'regex' as a key.")
                        continue
                    for key in keys:
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
                    if cls._DISALLOW_ACTION and "action" in item:
                        if item["action"] is not None:
                            ident = item.get("keyword") or item.get("regex") or "unknown"
                            logging.warning(f"Action not allowed in this context. Removing for: {ident}")
                        item["action"] = None  
                    converted.append(item)
                else:
                    try:
                        converted.append(str(item))
                    except ValueError:
                        logging.warning(f"Ignoring unexpected Error in config in field 'keywords': '{item}'.")
                        continue
            data["keywords"] = converted
        return data
    
class ContainerConfig(KeywordBase, ModularSettings):    
    """
    Model for per-container configuration, including keywords and setting overrides.
    """
    hosts: Optional[str] = None

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)
    
class SwarmServiceConfig(KeywordBase, ModularSettings):
    """
    Model for per-swarm service configuration, inheriting from ContainerConfig.
    """
    _DISALLOW_ACTION: ClassVar[bool] = True
    hosts: Optional[str] = None

class SystemdServiceConfig(KeywordBase, ModularSettings):
    """
    Model for per-systemd service configuration, inheriting from ContainerConfig.
    """
    _DISALLOW_ACTION: ClassVar[bool] = True

    hosts: Optional[str] = None
    custom_filters: Optional[List[str]] = None

class GlobalKeywords(BaseConfigModel, KeywordBase):
    pass

class NtfyConfig(BaseConfigModel):
    url: str 
    topic: str 
    token: Optional[SecretStr] = None
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    priority: Optional[Union[str, int]] = 3
    tags: Optional[str] = "kite,mag"

    @field_validator("priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)
class AppriseConfig(BaseConfigModel):  
    url: SecretStr 

class WebhookConfig(BaseConfigModel):
    url: str
    headers: Optional[dict]

class NotificationsConfig(BaseConfigModel):
    ntfy: Optional[NtfyConfig] = None
    apprise: Optional[AppriseConfig] = None
    webhook: Optional[WebhookConfig] = None

    @model_validator(mode="after")
    def check_at_least_one(self) -> "NotificationsConfig":
        if self.ntfy is None and self.apprise is None and self.webhook is None:
            logging.warning("You haven't configured any notification services. Notifications will not be sent.")
        return self

class GlobalConfig(BaseConfigModel):
    """Root configuration model for the application"""
    containers: dict[str, ContainerConfig] | None = None
    swarm_services: dict[str, SwarmServiceConfig] | None = None
    systemd_services: dict[str, SystemdServiceConfig] | None = None
    global_keywords: GlobalKeywords
    notifications: NotificationsConfig
    settings: Settings

    @model_validator(mode="before")
    def transform_legacy_format(cls, values):
        """Migrate legacy list-based container definitions to dictionary format."""
        # Convert list containers to dict format
        for container_object in ["containers", "swarm_services", "systemd_services"]:
            if isinstance(values.get(container_object), list):
                values[container_object] = {name: {} for name in values[container_object]}
            for container in values.get(container_object, {}):
                if isinstance(values.get(container_object).get(container), list):
                    values[container_object][container] = {
                        "keywords": values[container_object][container],
                    }
                elif values.get(container_object).get(container) is None:
                    values[container_object][container] = {
                        "keywords": [],
                    }
        return values
    
    @model_validator(mode="after")
    def check_at_least_one(self) -> "GlobalConfig":
        # Ensure at least one container or swarm service and at least one keyword is configured
        if not self.containers and not self.swarm_services and not self.systemd_services:
            raise ValueError("You have to configure at least one container")
        all_keywords = self.global_keywords.keywords.copy()
        if not all_keywords:
            for config in [self.containers, self.swarm_services, self.systemd_services]:
                if config:
                    for c in config.values():
                        all_keywords.extend(c.keywords)
                if all_keywords:
                    break
        if not all_keywords:
            raise ValueError("No keywords configured. You have to set keywords either per container or globally.")
        return self
    
def add_to_config(config, monitor_type, name, config_dict):
    try:
        new_config = None
        if monitor_type == "swarm" and name not in config.swarm_services:
            new_config = SwarmServiceConfig.model_validate(config_dict)
            config.swarm_services[name] = new_config
        elif monitor_type == "container" and name not in config.containers:
            new_config = ContainerConfig.model_validate(config_dict)
            config.containers[name] = new_config
        if new_config:
            pretty_config = prettify_config(new_config.model_dump(
                exclude_none=True, 
                exclude_defaults=False, 
                exclude_unset=False,
            ))
            return pretty_config
        return None
    except ValidationError as e:
        logging.error(f"Error adding to config: {e}")
    except Exception as e:
        logging.error(f"Unexpected error adding to config: {e}")
    return None


def format_pydantic_error(e: ValidationError) -> str:
    """Format Pydantic validation errors for user-friendly display."""
    error_messages = []
    for error in e.errors():
        location = ".".join(map(str, error["loc"]))
        msg = error["msg"]
        msg = msg.split("[")[0].strip()
        error_messages.append(f"Field '{location}': {msg}")
    return "\n".join(error_messages)


def prettify_config(data):
    """Recursively format config dict for display, masking secrets and ordering keys for readability."""
    if isinstance(data, dict):
        priority_keys = [k for k in ("regex", "keyword") if k in data]
        if priority_keys:
            rest_keys = [k for k in data.keys() if k not in priority_keys]
            ordered_dict = {k: data[k] for k in priority_keys + rest_keys}
            return {k: prettify_config(v) for k, v in ordered_dict.items()}
        return {k: prettify_config(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [prettify_config(item) for item in data]
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
        "excluded_keywords": [kw.strip() for kw in os.getenv("EXCLUDED_KEYWORDS", "").split(",") if kw.strip()] if os.getenv("EXCLUDED_KEYWORDS") else None
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

    if os.getenv("SYSTEMD_SERVICES"):
        env_config["systemd_services"] = {}
        for c in os.getenv("SYSTEMD_SERVICES", "").split(","):
            c = c.strip()
            env_config["systemd_services"][c] = {}


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

    config_dict = prettify_config(config.model_dump(
                                exclude_none=True, 
                                exclude_defaults=False, 
                                exclude_unset=False,
                                )
                            )
    yaml_output = yaml.dump(config_dict, default_flow_style=False, sort_keys=False, indent=4)
    logging.info(f"\n ------------- CONFIG ------------- \n{yaml_output}\n ----------------------------------")

    return config, config_path

