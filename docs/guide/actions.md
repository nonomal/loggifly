---
title: Actions
---


## Container Actions

You can configure automatic actions for your containers based on log patterns. 
Supported actions are `restart`, `stop` and `restart` and are configured per container. 

You can perform these actions on the monitored container itself or on other containers.

:::info
The `action_cooldown` default setting is 300 seconds (5 minutes) and has to be at least 10 seconds.
:::

### Perform actions on the monitored container

```yaml
containers:
  action_cooldown: 60  # 1 minute cooldown
  container3:
    - regex: error\b.*
      action: restart  # Restart the container when this regex is found
    - keyword: critical
      action: stop     # Stop the container when this keyword is found
    - keyword: timeout
      action: restart
```

### Perform actions on other containers

```yaml
containers:
  action_cooldown: 10  # 10 seconds cooldown
  container3:
    - regex: error\b.*
      action: restart@some-other-container  # Restart another container when this regex is found
    - keyword: critical
      action: stopsome-other-container     # Stop anoter container when this keyword is found
    - keyword: timeout
      action: restart@some-other-container
```

## Trigger OliveTin Actions

[OliveTin](https://github.com/OliveTin/OliveTin) is a great tool that allows you to perform predefined commands from a web interface. Fortunately for us it also has a API that we can use to trigger actions when LoggiFly finds certain keywords in the logs.

You can configure your OliveTin URL globally in the `settings` section or per `container` and even per `keyword`/`regex` in case you want to trigger commands on different OliveTin instances.

If you have configured a [Local User Login](https://docs.olivetin.app/security/local.html) you can use the `username` and `password` to trigger actions that require authentication.

Then you can configure the [`olivetin_action_id`](https://docs.olivetin.app/action_customization/ids.html) per keyword or regex.

Here is a an example config snippet:


```yaml
containers:
  container3:
    - regex: error\b.*
      olivetin_action_id: some-action-id

settings:
  olivetin_url: http://192.168.178.20:1337
  olivetin_username: admin
  olivetin_password: password

```