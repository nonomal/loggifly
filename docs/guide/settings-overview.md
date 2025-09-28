

# Settings Overview

It's important to understand how settings can be applied on three different levels (this applies to both normal `settings` and `notifications` settings).

The three levels are:
- Global (`settings` / `notifications`)
- Per container (`containers`)
- Per keyword or regex (`keyword` / `regex`)

::: details Here is an example of how settings can be applied on different levels

```yaml
containers:
  container1:
    notification_cooldown: 15
    notification_title: "{container}: {keywords}"
    keywords:
      - keyword: "error"
        notification_cooldown: 0
        notification_title: "Error in {container}"

settings:
  notification_cooldown: 5
  notification_title: "{keywords} found in {container}"
```
:::

When the same setting is defined in multiple places like in the example above, the following priority applies:

`keyword/regex > container > global`

This table shows which settings are available and where they can be configured:<br>


| Setting                         | Global (`settings`) | Per Container (`containers`) | Per Keyword (`keywords`) | Description |
|---------------------------------|--------------------|-------------------------------|--------------------------|-------------|
| `log_level`                      | ✅                   | –                             | –                     | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `multi_line_entries`            | ✅                   | –                             | –                      | Enable detection of multi-line log entries |
| `reload_config`                 | ✅                   | –                             | –                      | Automatically reload config on changes |
| `disable_start_message`         | ✅                   | –                             | –                      | Disable startup notification |
| `disable_shutdown_message`      | ✅                   | –                             | –                      | Disable shutdown notification |
| `disable_config_reload_message` | ✅                   | –                             | –                      | Disable notification when config is reloaded |
| `disable_container_event_message`| ✅                  | –                             | –                      | Disable notification when container monitoring starts/stops |
| `compact_summary_message`       | ✅                   | –                             | –                      | Formats the summary message in startup and config reload notifications with a comma-separated list of containers instead of a multi-line list|
| [`hosts`](./remote-hosts#assign-containers-to-hosts) | –     | ✅      | –             | Name of the host a container should be monitored on if monitoring multiple hosts |
| `disable_notifications`         | ✅                   | ✅                             | ✅                      | Disable notifications when keywords are found. Useful when you only want to trigger actions. |
| [`excluded_keywords`](./config_sections/settings#excluded-keywords) | ✅  | ✅  | ✅    | Log lines with these keywords will always be ignored | 
| `hide_regex_in_title`           | ✅                   | ✅                            | ✅                     | Exclude regex  from notification title for cleaner look | 
| `notification_cooldown`         | ✅                   | ✅                            | ✅                     | Seconds between repeated alerts per container and keyword |
| `notification_title`            | ✅                   | ✅                            | ✅                     | Template for the notification title (`{container}`, `{keywords}`) |
| `attachment_lines`              | ✅                   | ✅                            | ✅                     | Number of log lines to include in attachments |
| `attach_logfile`                | ✅                   | ✅                            | ✅                     | Attach log output to the notification (true/false) |
| `action_cooldown`               | ✅                   | ✅                            | ✅                      | Cooldown for triggering container actions per container and action (default: 300s, min: 10s) |
| `action`                        | –                    | –                             | ✅                      | Trigger container actions (restart/stop) |
| [`json_template`](./customize-notifications/json_template) | – | –                     | ✅                     | Template for JSON log entries |
| [`template`](./customize-notifications/template) | –   | –                             | ✅                      | Template for plain text log entries using named capturing groups |
| `olivetin_url`                  | ✅                   | ✅                            | ✅                      | URL of your OliveTin instance |
| `olivetin_username`             | ✅                   | ✅                            | ✅                      | Username for your OliveTin instance |
| `olivetin_password`             | ✅                   | ✅                            | ✅                      | Password for your OliveTin instance |
| `olivetin_action_id`            | –                    | –                             | ✅                      | OliveTin action ID |

The same applies to the `notifications` settings. You can set the same settings globally or per container or per keyword/regex. <br>

| Setting                         | Global (`notifications`) | Per Container (`containers`) | Per Keyword (`keywords`) | Description |
|---------------------------------|--------------------|-------------------------------|--------------------------|-------------|
| `apprise_url`                  | ✅ (`.apprise.url`)   | ✅                            | ✅                      | Apprise-compatible URL for notifications |
| `ntfy_url`                      | ✅ (`.ntfy.url`)     | ✅                            | ✅                 | ntfy server URL |
| `ntfy_topic`                    | ✅ (`.ntfy.topic`)   | ✅                            | ✅                 | ntfy topic |
| `ntfy_priority`                 | ✅ (`.ntfy.priority`)| ✅                            | ✅                 | ntfy priority (1–5) |
| `ntfy_tags`                     | ✅ (`.ntfy.tags`)    | ✅                            | ✅                 | Tags/emojis for ntfy notifications |
| `ntfy_token`                    | ✅ (`.ntfy.token`)   | ✅                            |✅                      | ntfy token for authentication |
| `ntfy_username`                 | ✅ (`.ntfy.username`) | ✅                            | ✅                     | ntfy username for authentication |
| `ntfy_password`                 | ✅ (`.ntfy.password`) | ✅                            | ✅                     | ntfy password for authentication |
| `webhook_url`                   | ✅ (`.webhook.url`)  | ✅                            | ✅                     | Custom webhook URL for notifications |
| `webhook_headers`               | ✅ (`.webhook.headers`) | ✅                            | ✅                     | Custom headers for webhook notifications |

> ✅ = supported<br>
> – = not supported
