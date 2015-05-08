#!/usr/bin/env python

import logging
import optparse
import struct

import xbee_controller


node_1 = 0x0013a200406899a9

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-r", "--remote_at_cmd",
                      action="store_true", dest="remote",
                      help="send AT command sequence to remote device")
    (options,args) = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)
    ctl = xbee_controller.XBeeController()

    cmd = args[0]
    if len(args) > 1:
        val = int(args[1])
    else:
        val = None

    if options.remote:
        r = ctl.remote_at_command(node_1, cmd, val)
    else:
        r = ctl.at_command(cmd, val)

    # decode the response
    for v in r:
        if len(v) == 0:
            print
        elif len(v) == 1:
            print ord(v[0])
        elif len(v) == 2:
            print struct.unpack(">H", v)[0]
        else:
            print v
