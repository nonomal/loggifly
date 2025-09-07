---
title: Config Structure
---

# Config Structure

The `config.yaml` file is divided into four main sections:

1. [**`settings`**](./config_sections/settings): Global settings for the whole program (_Optional since they all have default values_)
2. [**`notifications`**](./config_sections/notifications): Configure ntfy, apprise and/or a custom webhook
3. [**`containers`**](./config_sections/containers): Define which Containers to monitor and their specific Keywords (_plus optional settings_).
4. [**`global_keywords`**](./config_sections/global-keywords): Keywords that apply to _all_ monitored Containers.


> [!IMPORTANT]
For the program to function you need to configure:
>- **at least one container**
>- **at least one keyword / regex pattern (either set globally or per container)**
>
>  The rest is optional or has default values.

## Config Template

Here is an example config. This file automatically gets downloaded into your mounted `/config` directory when you start LoggiFly for the first time. 
::: details Config Template

<<< @/configs/config_template.yaml{yaml}

:::

