# LoggiFly v1.5.0 — Release Notes

This release brings a **better way to configure your containers, enhanced action support, a new keyword type and stronger performance & security**. With OliveTin support (incl. auth), docker labels for configuration, keyword groups and a new distroless image that is **2.3× smaller and far more secure**, LoggiFly is more flexible and secure than ever.

## 🚀 New Features

* **OliveTin Actions Integration**

  * Trigger OliveTin actions from log events.
  * Supports username/password authentication.
  * Configurable globally, per container, or per keyword.
  * A separate notification with execution details is sent for each action.
  * *[See docs](http://192.168.178.58:5173/loggifly/guide/actions.html#trigger-olivetin-actions).*

* **Cross-Container Actions (`action@target`)**

  * Run actions against other containers, e.g. `restart@some-other-container`.
  * *[See docs](http://192.168.178.58:5173/loggifly/guide/actions.html#perform-actions-on-other-containers)*

* **Per-Action Cooldowns (per container)**

  * Cooldowns are now tracked **per specific action string** (including target) **per container**.
    Example: `restart` and `restart@some-other-container` have separate cooldowns (for the container that they are configured for)
  * **Minimum** cooldown: **10s**. **Default** remains **300s**.

* **Keyword Groups**

  * Use `keyword_group` to trigger only when **all** keywords in a group are present.
  * *[See docs](http://192.168.178.58:5173/loggifly/guide/config_sections/containers.html#keyword-groups)*

* **Label-Based Configuration**

  * Configure containers or Swarm services via Docker labels (e.g. `loggifly.setting_name`, `loggifly.keywords`, …).
  * *[See docs](http://192.168.178.58:5173/loggifly/guide/config_sections/label-config)*

* **Disable Notifications**

  * New setting: `disable_notifications`
  * Suppress notifications globally, per container, or per keyword 
  * Useful for action-only workflows.

## ⚙️ Improvements

* **Performance**

  * **Reduced CPU usage**: instead of checking every second whether the buffer needs to be flushed (the buffer is where lines are combined into multi-line entries) flush threads now sleep and are only waken up temporarily to flush the buffer when new lines arrive.

* **Read-Only Container Support (Security)**

  * Attachments now work in **read-only** contexts
  * set `read_only: true` in your Compose file for better security

* **Distroless Image**

  * New distroless base image is **2.3× smaller** resulting in a reduced attack surface.
  * Significantly improves container security.

* **Configuration Validation**

  * Stronger regex & type checks, clearer error messages.

* **Notifications**

  * **Consolidated**: one combined notification message for all hosts (instead of one per host).

* **Refactoring**

  * More robust internals and error handling.

## 🐛 Bug Fixes

* Fixed: globally excluded keywords were not applied correctly.
* Fixed: container notification cooldown could not be set to `0`.

## 📖 Documentation

* New/updated sections for OliveTin, cross-container actions, cooldowns, keyword groups, label-based configuration, read-only mode, etc.

## 🔧 Configuration Changes

* **`LOGGIFLY_MODE`**

  * Previously required (`LOGGIFLY_MODE=swarm`) to monitor Swarm services.
  * This is **no longer necessary**, LoggiFly now automatically monitors Swarm services when they are configured.
  * The variable now only affects **notification titles**, adding context about the node (manager/worker) where the log line originated.

## 💡 Security Recommendations

For maximum security, here are some recommendations:

* Running LoggiFly with `read_only: true`
* Setting a non-root `user:` in your compose file
* Using a **socket proxy** to isolate Docker socket access
* Take a look at the new compose examples: [docs](http://192.168.178.58:5173/loggifly/guide/getting-started.html#docker-compose)

## 💡 Tip: Monitoring System Logs

A simple and secure way to capture system logs (e.g. failed SSH login attempts) is to use a **Fluentbit sidecar** that streams journal logs to container logs, where LoggiFly can monitor them. [See Docs](http://192.168.178.58:5173/loggifly/guide/examples.html#%F0%9F%94%8D-systemd-monitorings)

\[Insert screenshot: failed SSH login notification]


