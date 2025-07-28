import requests
import apprise
import base64
import logging
from pydantic import SecretStr
import urllib.parse
from load_config import GlobalConfig

logging.getLogger(__name__)

def get_ntfy_config(config, message_config, container_config):
    """
    Aggregate ntfy notification configuration from global, container, and message-specific sources.
    Precedence: message_config > container_config > global_config.
    Handles secret values and authorization header construction.
    """
    ntfy_config = {
        "topic": None,
        "tags": None,
        "priority": None,
        "url": None,
        "token": None,
        "username": None,
        "password": None,
        "authorization": ""
    }

    global_config = config.notifications.ntfy.model_dump(exclude_none=True) if config.notifications.ntfy else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    for key in ntfy_config.keys():
        ntfy_key = "ntfy_" + key
        if message_config.get(ntfy_key) is not None:
            ntfy_config[key] = message_config.get(ntfy_key)
        elif container_config.get(ntfy_key) is not None:
            ntfy_config[key] = container_config.get(ntfy_key)
        elif global_config.get(key) is not None:
            ntfy_config[key] = global_config.get(key)

    for key, value in ntfy_config.items():
        if value and isinstance(value, SecretStr):
            ntfy_config[key] = value.get_secret_value()

    if ntfy_config.get("token"):
        ntfy_config["authorization"] = f"Bearer {ntfy_config['token']}"
    elif ntfy_config.get('username') and ntfy_config.get('password'):
        credentials = f"{ntfy_config['username']}:{ntfy_config['password']}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        ntfy_config["authorization"] = f"Basic {encoded_credentials}"
    return ntfy_config


def get_apprise_url(config, message_config, container_config):
    """
    Retrieve the Apprise notification URL from message, container, or global config.
    Precedence: message_config > container_config > global_config.
    Handles secret values.
    """
    apprise_url = None
    global_config = config.notifications.apprise.model_dump(exclude_none=True) if config.notifications.apprise else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    if message_config.get("apprise_url"):
        apprise_url = message_config.get("apprise_url")
    elif container_config.get("apprise_url"):
        apprise_url = container_config.get("apprise_url")
    elif global_config.get("url"):
        apprise_url = global_config.get("url")

    if apprise_url and isinstance(apprise_url, SecretStr):
        apprise_url = apprise_url.get_secret_value() if apprise_url else None
    return apprise_url


def get_webhook_config(config, message_config, container_config):
    """
    Aggregate webhook configuration from global, container, and message-specific sources.
    Precedence: message_config > container_config > global_config.
    """
    webhook_config = {"url": None, "headers": {}}

    global_config = config.notifications.webhook.model_dump(exclude_none=True) if config.notifications.webhook else {}
    container_config = container_config.model_dump(exclude_none=True) if container_config else {}
    message_config = message_config if message_config else {}

    for key in webhook_config.keys():
        webhook_key = "webhook_" + key
        if message_config.get(webhook_key) is not None:
            webhook_config[key] = message_config.get(webhook_key)
        elif container_config.get(webhook_key) is not None:
            webhook_config[key] = container_config.get(webhook_key)
        elif global_config.get(key) is not None:
            webhook_config[key] = global_config.get(key)
    return webhook_config


def send_apprise_notification(url, message, title, file_path=None):
    """
    Send a notification using Apprise.
    Optionally attaches a file. Message is truncated if too long.
    """
    message = ("This message had to be shortened: \n" if len(message) > 1900 else "") + message[:1900]
    try:
        apobj = apprise.Apprise()
        apobj.add(url)
        if file_path is None:
            result = apobj.notify(
                title=title,
                body=message,
            )
        else:
            result = apobj.notify(
                title=title,
                body=message,
                attach=file_path
            )
        if result:
            logging.info("Apprise-Notification sent successfully")
        else:
            logging.error("Error while trying to send apprise-notification: %s", result)
    except Exception as e:
        logging.error("Error while trying to send apprise-notification: %s", e)


def send_ntfy_notification(ntfy_config, message, title, file_path=None):
    """
    Send a notification via ntfy with optional file attachment.
    Handles authorization and message truncation.
    """
    message = ("This message had to be shortened: \n" if len(message) > 3900 else "") + message[:3900]
    headers = {
        "Title": title,
        "Tags": f"{ntfy_config['tags']}",
        "Icon": "https://raw.githubusercontent.com/clemcer/loggifly/main/images/icon.png",
        "Priority": f"{ntfy_config['priority']}"
    }
    if ntfy_config.get('authorization'):
        headers["Authorization"] = f"{ntfy_config.get('authorization')}"

    try:
        if file_path:
            file_name = file_path.split("/")[-1]
            headers["Filename"] = file_name
            with open(file_path, "rb") as file:
                # When attaching a file the message can not be passed normally.
                # So if the message is short, include it as query param, else omit it
                if len(message) < 199:
                    response = requests.post(
                        f"{ntfy_config['url']}/{ntfy_config['topic']}?message={urllib.parse.quote(message)}",
                        data=file,
                        headers=headers
                    )
                else:
                    response = requests.post(
                        f"{ntfy_config['url']}/{ntfy_config['topic']}",
                        data=file,
                        headers=headers
                    )
        else:
            response = requests.post(
                f"{ntfy_config['url']}/{ntfy_config['topic']}",
                data=message,
                headers=headers
            )
        if response.status_code == 200:
            logging.info("Ntfy-Notification sent successfully")
        else:
            logging.error("Error while trying to send ntfy-notification: %s", response.text)
    except requests.RequestException as e:
        logging.error("Error while trying to connect to ntfy: %s", e)


def send_webhook(json_data, webhook_config):
    """
    Send a POST request to a custom webhook with the provided JSON payload and headers.
    """
    url, headers = webhook_config.get("url"), webhook_config.get("headers", {})
    try:
        response = requests.post(
            url=url,
            headers=headers,
            json=json_data,
            timeout=10
        )
        if response.status_code == 200:
            logging.info(f"Webhook sent successfully.")
            # logging.debug(f"Webhook Response: {json.dumps(response.json(), indent=2)}")
        else:
            logging.error("Error while trying to send POST request to custom webhook: %s", response.text)
    except requests.RequestException as e:
        logging.error(f"Error trying to send webhook to url: {url}, headers: {headers}: %s", e)


def send_notification(config: GlobalConfig, 
                      monitored_object_name, 
                      title=None, 
                      message=None,
                      message_config=None, 
                      container_config=None, 
                      hostname=None):
    """
    Dispatch a notification using ntfy, Apprise, and/or webhook based on configuration.
    Handles message formatting, file attachments, and host labeling.
    """
    message = message.replace(r"\n", "\n").strip() if message else ""
    monitor_type = message_config.get("monitor_type", "container") if message_config else "container"

    # If multiple hosts are set, prepend hostname to title
    title = f"[{hostname}] - {title}" if hostname else title
    file_path = message_config.get("file_path") if message_config else None

    ntfy_config = get_ntfy_config(config, message_config, container_config)
    if (ntfy_config and ntfy_config.get("url") and ntfy_config.get("topic")):
        send_ntfy_notification(ntfy_config, message=message, title=title, file_path=file_path)

    apprise_url = get_apprise_url(config, message_config, container_config)
    if apprise_url:
        send_apprise_notification(apprise_url, message=message, title=title, file_path=file_path)

    webhook_config = get_webhook_config(config, message_config, container_config)
    if (webhook_config and webhook_config.get("url")):
        keywords = message_config.get("keywords_found", None) if message_config else None
        json_data = {
            monitor_type: monitored_object_name,
            "keywords": keywords,
            "title": title,
            "message": message,
            "host": hostname
        }
        send_webhook(json_data, webhook_config)

