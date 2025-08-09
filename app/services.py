import requests
import logging
import threading
from config.config_model import GlobalConfig

class OlivetinAction:
    """
    Trigger action via Olivetin API.
    First authenticates with username/password to get a session cookie if username and password are provided.
    Then can use that cookie for subsequent action requests.
    """
    def __init__(self):
        self.auth_cookies = {}

    def get_auth_cookie(self, url, username, password):
        if (auth_cookie := self.auth_cookies.get(url)):
            if self.check_auth_cookie(url, auth_cookie):
                return auth_cookie
            else:
                self.auth_cookies.pop(url)
        try:
            login_url = f"{url}/api/LocalUserLogin"
            login_response = requests.post(
                url=login_url,
                headers={"accept": "application/json", "Content-Type": "application/json"},
                json={"username": username, "password": password}
            )
            
            if login_response.status_code != 200:
                logging.error(f"Olivetin login failed: {login_response.status_code} - {login_response.text}")
                return
            
            # Get the auth cookie
            auth_cookie = login_response.cookies.get("olivetin-sid-local")
            if not auth_cookie:
                logging.error("No auth cookie received from Olivetin")
                logging.error(f"Login Response: {login_response.text}")
                return
            logging.info("Olivetin login successful")
            self.auth_cookies[url] = auth_cookie
            return auth_cookie
        except Exception as e:
            logging.error(f"Error getting auth cookie: {e}")
            return

    def check_auth_cookie(self, url, auth_cookie):
        try:
            who_am_i_url = f"{url}/api/WhoAmI"
            who_am_i_response = requests.get(
                url=who_am_i_url,
                cookies={"olivetin-sid-local": auth_cookie}
            )
            if who_am_i_response.status_code != 200:
                logging.error(f"You are not logged in to Olivetin: {who_am_i_response.status_code} - {who_am_i_response.text}")
                return
            return who_am_i_response.json()
        except Exception as e:
            logging.error(f"You are not logged in to Olivetin: {e}")
            return
        
    def trigger_action(self, url, action_id, username=None, password=None):
        logging.debug(f"Olivetin config: {url}, {username}, {password}")
        auth_cookie = None
        if username and password:
            auth_cookie = self.get_auth_cookie(url, username, password)
            if not auth_cookie:
                logging.error("No auth cookie found")
                return
        try:
            action_url = f"{url}/api/StartActionByGetAndWait/{action_id}"
            if auth_cookie:
                cookies = {"olivetin-sid-local": auth_cookie}
            else:
                cookies = None
            logging.debug(f"Action URL: {action_url}, cookies: {cookies}")
            action_response = requests.get(
                url=action_url,
                cookies=cookies
            )
            if action_response.status_code == 200:
                logging.info("Olivetin action triggered successfully")
            else:
                logging.error(f"Olivetin action request failed: {action_response.status_code} - {action_response.text}")
            try:
                data = action_response.json()
                logging.debug(f"Action Response: {data}")
                return data
            except ValueError:
                logging.error("Invalid JSON response from Olivetin")
                return None
        except requests.RequestException as e:
            logging.error(f"Error connecting to Olivetin: {e}")
            return None

_olivetin_action = None
_lock = threading.Lock()

def perform_olivetin_action(config: GlobalConfig, message_config, action_id):
    url = message_config.get("olivetin_url", "").strip() or config.settings.olivetin_url or None
    username = message_config.get("olivetin_username", "").strip() or config.settings.olivetin_username or None
    password = message_config.get("olivetin_password", "").strip() or config.settings.olivetin_password or None
    global _olivetin_action, _lock
    with _lock:
        if _olivetin_action is None:
            _olivetin_action = OlivetinAction()
        response = _olivetin_action.trigger_action(url, action_id, username, password)
        if not response:
            return "Olivetin Action Failed", "Olivetin Action failed with no response"
        log_entry = response.get("logEntry", {})
        action_title = log_entry.get("actionTitle", "unknown action")
        action_icon = log_entry.get("actionIcon", "")
        message = "Output:\n" + log_entry.get("output", "")
        if log_entry.get("executionFinished") == True:
            title = f"Olivetin Action was run: {action_icon} {action_title}"
        else:
            title = f"Olivetin was not able to complete action: {action_icon} {action_title}"
        return title, message

