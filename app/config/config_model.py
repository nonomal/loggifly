from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr,
    ValidationError,
    Field,
    AfterValidator
)
from enum import Enum
from constants import Actions
from typing import List, Optional, Union, ClassVar, Annotated
import logging
import re
import copy

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
    disable_notifications: Optional[bool] = None
    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("action_cooldown", mode="before")
    def validate_action_cooldown(cls, v):
        return validate_action_cooldown(v)
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
    disable_notifications: Optional[bool] = None

    olivetin_url: Optional[str] = None
    olivetin_username: Optional[str] = None
    olivetin_password: Optional[SecretStr] = None

    @field_validator("ntfy_priority", mode="before")
    def validate_priority(cls, v):
        return validate_priority(v)

    @field_validator("action_cooldown", mode="before")
    def validate_action_cooldown(cls, v):
        if v is None:
            return None
        return validate_action_cooldown(v)

class KeywordItemBase(ModularSettings):
    json_template: Optional[str] = None
    action: Optional[str] = None
    olivetin_action_id: Optional[str] = None

    @field_validator("action")
    def validate_action(cls, v):
        if v and not any(a.value == v.split('@')[0] for a in Actions):
            return None
        return v

class RegexItem(KeywordItemBase):
    """
    Model for a regex-based keyword with optional settings.
    """
    regex: str
    template: Optional[str] = None

class KeywordItem(KeywordItemBase):
    """
    Model for a string-based keyword with optional settings.
    """
    keyword: str

class KeywordGroup(KeywordItemBase):
    """
    Model for a group of keywords.
    """
    keyword_group: List[Union[str, KeywordItem, RegexItem]] = []

class KeywordBase(BaseModel):
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
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword', 'regex' or 'keyword_group' as a key.")
                        continue
                    elif "keyword_group" in item and not isinstance(item["keyword_group"], list):
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: You have to set 'keyword_group' as a list.")
                        continue
                    elif "regex" in item and not validate_regex(item["regex"]):
                        logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: Invalid regex.")
                        continue
                    for key in keys:
                        if key == "action":
                            if (not isinstance(item["action"], str) 
                            or not 0 < len(item["action"].split('@')) < 3 
                            or not any(action.value in item["action"].split('@')[0] for action in Actions)):
                                logging.warning(f"Ignoring Error in config in field {get_kw_or_rgx(item)}: Invalid action: '{item['action']}'.")
                                item["action"] = None
                            elif cls._DISALLOW_ACTION and len(item["action"].split('@')) < 2:
                                logging.warning(f"Actions on swarm containers/services are not allowed. Removing action '{item['action']}' for {get_kw_or_rgx(item)}")
                                item["action"] = None
                        if isinstance(item[key], int):
                            item[key] = str(item[key])
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
        if not self.containers and not self.swarm_services:
            raise ValueError("You have to configure at least one container")
        all_keywords = copy.deepcopy(self.global_keywords.keywords)
        if not all_keywords:
            for config in [self.containers, self.swarm_services]:
                if config:
                    for c in config.values():
                        all_keywords.extend(c.keywords)
                if all_keywords:
                    break
        if not all_keywords:
            raise ValueError("No keywords configured. You have to set keywords either per container or globally.")
        return self

def validate_action_cooldown(v):
    if v is None:
        return None
    try:
        v = int(v)
    except ValueError:
        return None
    if v < 10:
        logging.warning("Action cooldown must be at least 10 seconds. Setting to 10 seconds")
        return 10
    return v


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

def get_kw_or_rgx(item):
    if isinstance(item, dict):
        if "keyword" in item:
            return f"keyword: '{item['keyword']}'"
        elif "regex" in item:
            return f"regex: '{item['regex']}'"
        elif "keyword_group" in item:
            return f"keyword_group: '{item['keyword_group']}'"
    return "unknown"