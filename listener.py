#!/usr/bin/env python

import time
import logging
from xbee_controller import XBeeController


def on_api_frame(address, strength, data):
    print "%d %i" % (time.time(), data['dio'])


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    ctl = XBeeController()
    ctl.on_api_frame = on_api_frame

    while True:
        ctl.receive()
