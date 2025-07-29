def generate_message(monitored, unmonitored, monitor_type_placeholder, host=None):
    if host:
        message = f"[{host}]\n"
    else:
        message = ""
    if monitored:
        message = f"These {monitor_type_placeholder}s are being monitored:\n - {'\n - '.join(monitored)}"
    else:
        message = f"No {monitor_type_placeholder} are being monitored. Waiting for new {monitor_type_placeholder}s..."
    if unmonitored:
        message = message + (f"\n\nThese {monitor_type_placeholder}s are not running:\n - {'\n - '.join(unmonitored)}")
    return message
