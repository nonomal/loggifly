
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr    
)
from typing import Dict, List, Optional, Union
import os
import logging
import yaml

logging.getLogger(__name__)

""" 
THIS MAY LOOK UNNECESSARILY COMPLICATED BUT I WANTED TO LEARN AND USE PYDANTIC 
I DIDN'T MANAGE TO USE PYDANTIC WITH ENVIRONMENT VARIABLES THE WAY I WANTED. 
I NEEDED ENV TO OVERRIDE YAML DATA AND YAML TO OVERRIDE DEFAULT VALUES AND I COULD NOT GET IT TO WORK
SO NOW I FIRST LOAD THE YAML AND THE ENVIRONMENT VARIABLES, MERGE THEM AND THEN I VALIDATE THE DATA WITH PYDANTIC
"""
class NtfyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    url: str = Field(..., description="Ntfy server URL")
    topic: str = Field(..., description="Ntfy topic name")
    token: Optional[SecretStr] = Field(default=None, description="Optional access token")
    priority: Optional[Union[str, int]] = Field(default=3, description="Message priority 1-5")
    tags: Optional[str] = Field("kite,mag", description="Comma-separated tags")

    @field_validator("priority")
    def validate_priority(cls, v):
        if isinstance(v, str):
            try:
                v = int(v)
            except ValueError:
                pass
        if isinstance(v, int):
            if not 1 <= int(v) <= 5:
                raise ValueError("Priority must be between 1-5")
        if isinstance(v, str):
            options = ["max", "urgent", "high", "default", "low", "min"]
            if v not in options:
                raise ValueError(f"Priority must be one of {options} or a number between 1-5")
        return v

class AppriseConfig(BaseModel):  
    model_config = ConfigDict(extra="forbid", validate_default=True)
    url: SecretStr = Field(..., description="Apprise compatible URL")

class NotificationsConfig(BaseModel):
    ntfy: Optional[NtfyConfig] = Field(default=None, validate_default=False)
    apprise: Optional[AppriseConfig] = Field(default=None, validate_default=False)

    @model_validator(mode="after")
    def check_at_least_one(self) -> "NotificationsConfig":
        if self.ntfy is None and self.apprise is None:
            raise ValueError("At least on of these two Apprise / Ntfy has to be configured.")
        return self

class ContainerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    ntfy_tags: Optional[str] = Field(default=None, validate_default=False) 
    ntfy_topic: Optional[str] = None
    ntfy_priority: Optional[int] = None
    attachment_lines: Optional[int] = None
    notification_cooldown: Optional[int] = None
    keywords: List[Union[str, Dict[str, str]]] = []
    keywords_with_attachment: List[str] = []

    @field_validator("ntfy_priority")
    def validate_priority(cls, v):
        if isinstance(v, str):
            try:
                v = int(v)
            except ValueError:
                pass
        if isinstance(v, int):
            if not 1 <= int(v) <= 5:
                raise ValueError("Priority must be between 1-5")
        if isinstance(v, str):
            options = ["max", "urgent", "high", "default", "low", "min"]
            if v not in options:
                raise ValueError(f"Priority must be one of {options}")
        return v
class GlobalKeywords(BaseModel):
    keywords: List[str] = []
    keywords_with_attachment: List[str] = []




class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    
    log_level: str = Field("INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")
    notification_cooldown: int = Field(5, description="Cooldown in seconds for repeated alerts")
    attachment_lines: int = Field(20, description="Number of log lines to include in attachments")
    multi_line_entries: bool = Field(True, description="Enable multi-line log detection")
    disable_start_message: bool = Field(False, description="Disable startup notification")
    disable_shutdown_message: bool = Field(False, description="Disable shutdown notification")
    disable_restart_message: bool = Field(False, description="Disable config reload notification")
    disable_restart: bool = Field(False, description="Disable restart on config change")

class GlobalConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_default=True
    )
    containers: Dict[str, ContainerConfig]
    global_keywords: GlobalKeywords
    notifications: NotificationsConfig
    settings: Settings

    @model_validator(mode="before")
    def transform_legacy_format(cls, values):
    
        # Convert legacy global_keywords format
        if isinstance(values.get("global_keywords"), list):
            values["global_keywords"] = {
                "keywords": values["global_keywords"],
                "keywords_with_attachment": []
            }

        # Convert list containers to dict format
        if isinstance(values.get("containers"), list):
            values["containers"] = {
                name: {} for name in values["containers"]
            }

         # Convert legacy keywords format per container
        for container in values.get("containers"):
            if isinstance(values.get("containers").get(container), list):
                values["containers"][container] = {
                    "keywords": values["containers"][container],
                    "keywords_with_attachment": []
                }
            elif values.get("containers").get(container) is None:
                values["containers"][container] = {
                    "keywords": [],
                    "keywords_with_attachment": []
                }
        return values
    
    @model_validator(mode="after")
    def check_at_least_one(self) -> "NotificationsConfig":
        tmp_list = []
        if not self.global_keywords.keywords and not self.global_keywords.keywords_with_attachment:
            for k in self.containers:
                tmp_list.extend(self.containers[k].keywords)
        else:
            return self
        if not tmp_list:
            print("HEY")
            raise ValueError("No keywords configured. You have to set keywords either per container or globally.")
        return self

    @field_validator("containers")
    def validate_priority(cls, v):
        if isinstance(v, dict):
            if not v:
                raise ValueError(f"You have to configure at least one container")
        return v


def merge_yaml_and_env(yaml, env_update):
    for key, value in env_update.items():
        if isinstance(value, dict) and key in yaml:
            merge_yaml_and_env(yaml[key],value)
        else:
            if value is not None:
                yaml[key] = value
    return yaml


def load_config(path="/app/config.yaml"):
    yaml_config = {}
    if os.path.isfile(path):
        try:
            with open(path, "r") as file:
                yaml_config = yaml.safe_load(file)
                logging.info("config.yaml succesfully loaded.")
                no_config_file = False
        except FileNotFoundError:
            logging.warning("config.yaml not found. Only using environment variables.")
            no_config_file = True
    else:
        logging.warning("config.yaml not found. Only using environment variables.")
        no_config_file = True
    """
    -------------------------LOAD ENVIRONMENT VARIABLES---------------------
    """
    env_config = { "notifications": {}, "settings": {}, "global_keywords": {}, "containers": {}}
    settings_values = {
        "log_level": os.getenv("LOG_LEVEL"),
        "attachment_lines": os.getenv("ATTACHMENT_LINES"),
        "multi_line_entries": os.getenv("MULTI_LINE_ENTRIES"),
        "notification_cooldown": os.getenv("NOTIFICATION_COOLDOWN"),
        "disable_restart": no_config_file if no_config_file is True else os.getenv("DISABLE_RESTART"),
        "disable_start_message": os.getenv("DISABLE_START_MESSAGE"),
        "disable_restart_message": os.getenv("DISABLE_RESTART_MESSAGE"),
        "disable_shutdown_message": os.getenv("DISABLE_SHUTDOWN_MESSAGE")
        } 
    ntfy_values =  {
        "url": os.getenv("NTFY_URL"),
        "topic": os.getenv("NTFY_TOPIC"),
        "token": os.getenv("NTFY_TOKEN"),
        "priority": os.getenv("NTFY_PRIORITY"),
        "tags": os.getenv("NTFY_TAGS"),
        }
    apprise_values = {
        "url": os.getenv("APPRISE_URL")
    }


    global_keywords_values = {
        "keywords": [kw.strip() for kw in os.getenv("GLOBAL_KEYWORDS", "").split(",") if kw.strip()] if os.getenv("GLOBAL_KEYWORDS") else [],
        "keywords_with_attachment": [kw.strip() for kw in os.getenv("GLOBAL_KEYWORDS_WITH_ATTACHMENT", "").split(",") if kw.strip()] if os.getenv("GLOBAL_KEYWORDS_WITH_ATTACHMENT") else [],
    }
    if os.getenv("CONTAINERS"):
        for c in os.getenv("CONTAINERS", "").split(","):
            c = c.strip()
            env_config["containers"][c] = {}
    if any(ntfy_values.values()):
        env_config["notifications"]["ntfy"] = ntfy_values
    if apprise_values["url"]: 
        env_config["notifications"]["apprise"] = apprise_values
    for k, v in global_keywords_values.items():
        if v:
            env_config["global_keywords"][k]= v
    for key, value in settings_values.items(): 
        if value is not None:
            env_config["settings"][key] = value

    merged_config = merge_yaml_and_env(yaml_config, env_config)


    config = GlobalConfig.model_validate(merged_config)
    logging.info(f"\n ------------- CONFIG ------------- \n{config.model_dump_json(indent=2, exclude_none=True)}\n ----------------------------------")

    return config

