**\[Release] LoggiFly v1.5.0 – Smaller, Safer, Smarter 🚀**

Hey selfhosters,

LoggiFly v1.5.0 is out! 

LoggiFly is a Docker log monitoring tool that can send notifications and even trigger actions when certain keywords appear in container logs.

This release is mostly about **security and flexibility**:

* **2.3× smaller** distroless image
* Works in **read-only mode**
* New best practices: use a **Docker socket proxy**, set a dedicated user, and mount read-only whenever possible

Feature highlights:

* OliveTin actions integration (with auth)
* Cross-container actions (`restart@other-container`)
* Keyword Groups (only trigger notifications when all keywords from one group are found)
* Docker Label-based configuration

Full notes: \[GitHub link]

---

### A quick note on system logs 🖥️

At one point, I was playing around with a solution that would have allowed **systemd monitoring integrated into LoggiFly**. But it would have bloated the image (2.5× larger), broken distroless, and reduced security by _a lot_.

Another reason for deciding against it was that there is actually a very simple alternative.
You can set up a **Fluentbit container** to forward system logs (e.g. failed SSH attempts) to its Docker container logs where LoggiFly takes over and monitors them. Much leaner, more secure, and fits LoggiFly’s purpose perfectly. More details in the [docs](http://192.168.178.58:5173/loggifly/guide/examples.html#%F0%9F%94%8D-systemd-monitoring)

Here’s an example of a failed SSH login being caught via Fluentbit → LoggiFly:
*\[Screenshot]*

