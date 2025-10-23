---
title: Settings Section
---

# Settings

These are all the possible global settings you can set in the config.yaml.<br> 
Configuring these settings is optional since they all have default values.<br>

```yaml
settings:          
  log_level: INFO                         # DEBUG, INFO, WARNING, ERROR
  multi_line_entries: True                # Catch log entries that span multiple lines instead of going line by line.
  reload_config: True                     # Auto-reload config on changes
  disable_start_message: False            # Suppress startup notification
  disable_shutdown_message: False         # Suppress shutdown notification
  disable_config_reload_message: False    # Suppress config reload notification
  disable_container_event_message: False  # Suppress container start/stop notifications
  disable_notifications: False            # Suppress notifications from log events (useful for action-only workflows)
  compact_summary_message: False          # comma-separated list of containers in startup and config reload notifications
  monitor_all_containers: False        # Monitor all containers on the host
  monitor_all_swarm_services: False    # Monitor all swarm services on the host
  excluded_containers:                  # List of containers that should not be monitored
  excluded_swarm_services:              # List of swarm services that should not be monitored

  # The following settings can also be set per container or per keyword/regex pattern (see containers section)
  notification_cooldown: 5            # Seconds between alerts for same keyword (per container)
  action_cooldown: 300                # Cooldown (seconds) before next container action (min 60s)
  attach_logfile: False               # Attach log file to all notifications
  attachment_lines: 20                # Lines to include in log attachments
  hide_regex_in_title: False          # Hide regex pattern in notification title
  notification_title: default         # Custom template for notification title
  excluded_keywords:                  # List of keywords that will always be ignored in log lines. See the section below for how to configure these
```
<br>

---

# Further Explanations of some settings 

## Notification Title

When `notification_title: default` is set LoggiFly uses its own notification titles.
However, if you prefer something simpler or in another language, you can choose your own template for the notification title. 
This setting can also be configured per container and per keyword.

:::info
These are the keys that can be inserted into the template:
- `keyword` / `keywords`: _The keyword(s) that were found in a log line (they have the same value)_
- `container`: _The name of the container in which the keywords have been found_
:::

Here is an example:

```yaml
notification_title: "The following keywords were found in {container}: {keywords}"
```
Or keep it simple:
```yaml
notification_title: {container}
```

## Excluded Keywords

With this setting you can specify keywords that should _always_ be ignored. This is useful when you don't want to get notifications from irrelevant log lines.

`excluded_keywords` are set like this:

```yaml
settings:
  excluded_keywords:
    - keyword1
    - regex: regex-pattern1
    - keyword: keyword2
```

## Monitor All Containers / Swarm Services

With the `monitor_all_containers` and `monitor_all_swarm_services` settings you can monitor all containers or swarm services on the host. 
If you want to exclude certain containers or swarm services from monitoring, you can use the `excluded_containers` and `excluded_swarm_services` settings.<br>
Note that you can exclude swarm services by their service name or stack name.

```yaml
settings:
  monitor_all_containers: true
  monitor_all_swarm_services: true
  excluded_containers:
    - postgres-db
  excluded_swarm_services:
    - stack1_service1
    - stack2 
```

