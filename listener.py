#!/usr/bin/env python

# listens for messages from the XBee and dispatches the readings to a graphite
# server

# TODO: handle incoming data in a separate thread, so that we get accurate
# timestamps even when the sender thread gets behind
#
# TODO: run under supervisord
#
# TODO: rotate the logfiles
#
# TODO: warn if we do not get a reading for a while
#
# TODO: reduce sample frequency

import logging
import shutil
import socket
import time
import requests

from xbee_controller import XBeeController

CACERTS_PATH = '/etc/ssl/certs/ca-certificates.crt'

STATE_FILE = '/var/run/xbee/state'

# connect via IP to force a connection over the VPN
CARBON_SERVER = '10.87.87.1'
CARBON_PORT = 2003
GRAPHITE_SERVER = "https://graphite.sw1v.org"
CARBON_METRIC = "19cw.gas.usage"

logger = logging.getLogger(__name__)


class CarbonClient(object):
    def __init__(self):
        self.sock = None

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


class GraphiteClient(object):
    """client for the graphite REST api"""
    def __init__(self):
        self.base_url = GRAPHITE_SERVER

        # configure requests to trust our ca cert
        self.session = requests.session()
        self.session.verify = CACERTS_PATH

    def get_data(self, metric, **kwargs):
        """
        read raw data from the graphite server

        :param metric: metric to read
        :param kwargs: other parameters to pass in call
        :return: list of [value, time] pairs
        """
        kwargs['target'] = metric
        kwargs['format'] = 'json'
        url = "%s/render" % self.base_url
        r = self.session.get(url, params=kwargs)
        r.raise_for_status()
        result = r.json()
        assert len(result) >= 1, "unknown metric %s" % metric
        return result[0]['datapoints']


class Counter(object):
    def __init__(self):
        self.counter = 0
        self.last = None
        self.carbon_client = CarbonClient()

    def _read_state_file(self):
        with open(STATE_FILE) as f:
            r = f.readline().rstrip('\n')
            return int(r)

    def _read_state_from_server(self):
        graphite_client = GraphiteClient()
        data = graphite_client.get_data(metric=CARBON_METRIC)
        assert len(data) >= 1, "Unable to intialise from state file, and " \
                               "graphite server returned no data"
        # data is returned as a list of [value, time] pairs. get the last
        # known value.
        return data[-1][0]

    def load_state(self):
        try:
            self.counter = self._read_state_file()
            logger.info("initialised state from state file: %i",
                        self.counter)
        except IOError, e:
            logger.warn("Error reading from state file %s: %s. Attempting to "
                        "load from graphite server", STATE_FILE, e)
            self.counter = self._read_state_from_server()
            logger.info("initialised state from graphite server: %i",
                        self.counter)

    def save_state(self):
        tmp = STATE_FILE+".new"
        with open(tmp, "w") as f:
            f.write("%i\n" % self.counter)
        shutil.move(tmp, STATE_FILE)

    def on_api_frame(self, address, strength, data):
        reading = data['dio']
        if self.last is not None:
            inc = reading - self.last
            if inc < 0:
                inc += 16
            self.counter += inc
        else:
            logger.info("initialised with first reading=%i", reading)
        self.last = reading

        self.save_state()

        try:
            self.carbon_client.write("%s %i %i\n" % (
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
