---
title: Examples
---

# Examples 

## 📝 Config Example

Here is an example config with some real use cases. 
::: details Config Example with Use Cases

<<< @/configs/config_example.yaml{yaml}

:::

::: info
Feel free to contribute your use cases to [the file](https://github.com/clemcer/loggifly/blob/main/docs/configs/config_example.yaml).
:::

## 🔍 Systemd Monitoring

There once were plans to integrate systemd-monitoring into LoggiFly, but it was never implemented because it brought too many disadvantages. <br>
However, you can still monitor systemd services / journal logs with LoggiFly by setting up a fluentbit container.

With this compose file journal logs are directly streamed to the fluentbit container logs where LoggiFly can then monitor them.

```yaml
services:
  fluentbit:
    image: fluent/fluent-bit:latest
    container_name: fluentbit
    read_only: true
    volumes:
      - /var/log/journal:/var/log/journal:ro
    command: >
      /fluent-bit/bin/fluent-bit
      -i systemd -p tag=journal -p path=/var/log/journal -p read_from_tail=true
      -o stdout -p match=* -p format=json_lines
    restart: unless-stopped
```

