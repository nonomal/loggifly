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
import logging
import re


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

class KeywordGroup(ModularSettings):
    """
    Model for a group of keywords.
    """
    keyword_group: List[Union[str, KeywordItem, RegexItem]] = []
    json_template: Optional[str] = None
    action: Optional[ActionEnum] = None

class KeywordBase(BaseModel):
    """
    Base model for keyword lists, with pre-validation to handle legacy and misconfigured entries.
    """
    _DISALLOW_ACTION: ClassVar[bool] = False

    keywords: List[Union[str, KeywordItem, RegexItem, KeywordGroup]] = []

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
                    if "keyword" not in item and "regex" not in item and "keyword_group" not in item:
                        logging.warning(f"Ignoring Error in config in field 'keywords': '{item}'. You have to set 'keyword', 'regex' or 'keyword_group' as a key.")
                        continue
                    if "keyword_group" in item and not isinstance(item["keyword_group"], list):
                        logging.warning(f"Ignoring Error in config in field 'keywords': '{item}'. You have to set 'keyword_group' as a list.")
                        continue
                    if "regex" in item and not validate_regex(item["regex"]):
                        logging.warning(f"Ignoring Error in config in field 'keywords': '{item}'. Invalid regex.")
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

def validate_regex(v):
    try:
        re.compile(v)
    except re.error as e:
        logging.warning(f"Error in config for regex: '{v}'. Invalid regex. {e}")
        return False 
    return True