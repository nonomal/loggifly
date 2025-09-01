---
title: Configuration via DockerLabels
---

# Configuration via Docker Labels

You can configure LoggiFly via Docker labels. This allows you to configure LoggiFly without having to edit the config file.

You can use pretty much every setting via Docker labels. This includes notifications, keywords, actions, etc on `container` and on `keyword` / `regex` level.


Every label has to start with `loggifly` and you have to set `loggifly.monitor` to `true` for the container to be monitored. If you set it to `false` the container will always be ignored even it is configured in your `config.yaml`.

Container-level settings are set via `loggifly.<setting>`. 

To provide a simple list of keywords, you can set `loggifly.keywords` to a comma-separated list of keywords. The same applies for `loggifly.excluded_keywords`.

If you want to set keyword-level settings, you can do so by setting `loggifly.keywords.<index>.<setting>`. 
So if you wanted to set a regex with a notification title, you can do so by setting `loggifly.keywords.1.regex: "some-regex"` and `loggifly.keywords.1.notification_title: "some-title"`.

## Example

```yaml
services:
  container1:
    image: my-container
    labels:
      loggifly.monitor: "true" # has to be set

      # container-level settings
      loggifly.apprise_url: "discord://webhook-url"
      loggifly.ntfy_tags: "closed_lock_with_key"
      loggifly.ntfy_priority: "3"
      loggifly.attach_logfile: "true" # always attach the logfile to the notification for this container
      
      # simple keyword with notification title
      loggifly.keywords.0: "critical" 
      loggifly.keywords.0.notification_title: "{container}: Critical Alert"
      
      # regex with ntfy tags and hide_regex_in_title
      loggifly.keywords.1.regex: "download.*failed" 
      loggifly.keywords.1.ntfy_tags: "partying_face"
      loggifly.keywords.1.hide_regex_in_title: "true"
      
      # simple keyword with actions
      loggifly.keywords.2.keyword: "timeout" 
      loggifly.keywords.2.action: "restart"

      # simple comma-separated lists for keywords and excluded keywords
      loggifly.keywords: "keyword1,keyword2,keyword3"
      loggifly.excluded_keywords: "keyword4,keyword5,keyword6"
