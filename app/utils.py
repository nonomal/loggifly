def generate_message(monitored, unmonitored, monitor_type_placeholder):
    message = ""
    if monitored:
        monitored_message = "\n - ".join(monitored)
        message += f"These {monitor_type_placeholder} are being monitored:\n - {monitored_message}"
    else:
        message += f"No {monitor_type_placeholder} are being monitored. Waiting for new {monitor_type_placeholder}s..."
    if unmonitored:
        unmonitored_message = "\n - ".join(unmonitored)
        message += (f"\n\nThese {monitor_type_placeholder} are not running:\n - {unmonitored_message}")
    return message
