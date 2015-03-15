#!/usr/bin/env python

# listens for messages from the XBee and dispatches the readings to a graphite
# server

import logging
import shutil
import socket
import time

from xbee_controller import XBeeController

# TODO: move this somewhere where it won't get lost?
STATE_FILE = '/var/run/xbee/state'

CARBON_SERVER = '10.87.87.1'
CARBON_PORT = 2003
CARBON_METRIC = "19cw.gas.usage"

logger = logging.getLogger(__name__)


class Counter(object):
    counter = 0
    last = None
    sock = None

    def load_state(self):
        with open(STATE_FILE) as f:
            r = f.readline().rstrip('\n')
            self.counter = int(r)

    def save_state(self):
        tmp = STATE_FILE+".new"
        with open(tmp,"w") as f:
            f.write("%i\n" % self.counter)
        shutil.move(tmp, STATE_FILE)

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect((CARBON_SERVER, CARBON_PORT))

    def write(self, msg):
        logger.debug("Sending message to graphite server: %s",
                     msg.rstrip('\n'))

        if self.sock is None:
            self.connect()

        try:
            self.sock.sendall(msg)
        except socket.error, e:
            logger.warn("error from socket (will retry): %s", e)

            # try again; if it fails now we raise the exception
            self.connect()
            self.sock.sendall(msg)

    def on_api_frame(self, address, strength, data):
        reading = data['dio']
        if self.last is not None:
            inc = reading - self.last
            if inc < 0:
                inc += 16
            self.counter += inc
        else:
            logger.info("initialised with first reading=%i" % reading)
        self.last = reading

        self.save_state()

        try:
            self.write("%s %i %i\n" % (
                CARBON_METRIC,
                self.counter,
                time.time()))
        except socket.error:
            logger.exception("Error sending reading to graphite server")

if __name__ == "__main__":
    logging.basicConfig(
        filename="/var/log/xbee.log",
        format="%(asctime)-15s %(levelname)-5s %(name)s:%(message)s",
        level=logging.DEBUG)

    logger.info("Starting")

    counter = Counter()
    counter.load_state()

    ctl = XBeeController()
    ctl.on_api_frame = counter.on_api_frame

    while True:
        ctl.receive()
