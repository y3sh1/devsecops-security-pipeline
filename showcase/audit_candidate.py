"""Example of logging only the number of request headers."""
import logging


def record_request(handler):
    logging.info("header count = %d", len(handler.headers))
