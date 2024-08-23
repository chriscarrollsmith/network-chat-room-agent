import logging
import queue
from logging.handlers import QueueHandler, QueueListener


def configure_logger():
    # Configure the root logger
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Create handlers
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)

    # Create a queue for sharing log messages across threads
    log_queue = queue.Queue(-1)

    # Set up the queue handler
    queue_handler = QueueHandler(log_queue)
    root.addHandler(queue_handler)

    # Set up the listener
    listener = QueueListener(log_queue, console_handler)
    listener.start()
