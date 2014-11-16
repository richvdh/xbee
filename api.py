#!/usr/bin/env python

import optparse
import os
import select
from struct import calcsize,pack,unpack
import sys
import termios
import time

class XBeeController(object):
    AT_COMMAND=0x08
    AT_COMMAND_RESPONSE = 0x88

    def __init__(self, dev="/dev/ttyS1"):
        self.fh=open('/dev/ttyS1','rw+',0)
        self.configure()

    def configure(self):
        flags = termios.tcgetattr(self.fh)
   
        flags[3] &= ~termios.CRTSCTS # cflag
        flags[4] = termios.B9600 # ispeed
        flags[5] = termios.B9600 # ospeed

        termios.tcsetattr(self.fh, termios.TCSANOW, flags)
        termios.tcsendbreak(self.fh, 0)

    def read_frame(self):
        """
        wait for an API frame, and read it

        returns: list of bytes
        """
        while True:
            ch = self.fh.read(1)
            if ord(ch) == 0x7e:
                break
            print "<<< ",ch

        len_bytes = self.fh.read(2)
        length = unpack(">H",len_bytes)
        frame = self.fh.read(length[0])
        cs = self.fh.read(1)

        print "<<< ",
        for a in ch + len_bytes + frame + cs:
            print ("%02x" % ord(a)),
        print

        frame = [ord(f) for f in frame]
        if ord(cs) != 0xFF - (sum(frame) & 0xFF):
            raise Exception("mismatched checksum")
        return frame

    def send_frame(self, api_identifier, api_frame):
        """
        send an API frame

        api_identifier: integer api identifier
        api_frame: list of bytes

        returns: frame number
        """

        frame_no = 1
        frame = [api_identifier, frame_no] + [b for b in api_frame]
        checksum = 0xFF - (sum(frame) & 0xFF)
        len_bytes = pack(">BH",0x7E,len(frame))
        string = len_bytes + ''.join([chr(f) for f in frame]) + \
                 chr(checksum)

        print ">>> ",
        for a in string:
            print ("%02x" % ord(a)),
        print

        self.fh.write(string)
        return frame_no

    def at_command(self, cmd, multi_response=False):
        """send an AT command using the API, and return the result

        cmd: 2-letter AT command

        multi_response: True if command results in multiple responses. In this
          case, response will be a list

        returns: result bytes

        """

        print ">> %s" % cmd
        api_frame = [ord(cmd[0]),ord(cmd[1])]
        frame_no = self.send_frame(self.AT_COMMAND, api_frame)

        results = []
        while True:
            resp=self.read_frame()

            if resp[1] != frame_no:
                raise Exception("Unexpected seqno %02x" % resp[1])

            if resp[0] != self.AT_COMMAND_RESPONSE:
                raise Exception("Unexpected response type %02x" % rt)

            if resp[4] != 0:
                print "<< ERROR %i" % resp[4]
                raise Exception("Error from API command")

            result = resp[5:]
            print "<< OK %s" % (" ".join(("%02x" % b for b in result)))

            if not multi_response:
                return result

            if len(result) == 0:
                return results

            results.append(result)
                
            if multi_response and len(result) == 0:
                return results


def writer(ctl):
    r = ctl.at_command("ND", True)
    for node in r:
        nodestr = "".join((chr(b) for b in node))
        fmt = ">HLLB"
        fmtlen = calcsize(fmt)
        (my,sh,sl,db) = unpack(fmt,nodestr[0:fmtlen])
        ni = nodestr[fmtlen:-1]

        print "MY: %04x" % my
        print "SH: %08x" % sh
        print "SL: %08x" % sl
        print "DB: %02x" % db
        print "NI: %s" % ni
        print

def await_at_response(fh, timeout=3):
    buf=""
    end = time.time()+timeout

    while True:
        sleep = end-time.time()
        if sleep < 0:
            break
        (r,w,e) = select.select([fh], [], [fh], sleep)

        if fh not in r and fh not in e:
            continue
        r = fh.read(1)
        if r == '\r' or r == '\n':
            print "<< %s" % buf
            return buf
        buf += r
    if buf != "":
        print "<< %s" % buf
    return buf

def send_command(fd,command):
    print ">> %s" % command
    fd.write(command + "\r")

def read_nd_response(fd):
    empty_lines = 1
    # two successive empty lines ends the output
    while empty_lines < 2:
        r = await_at_response(fd)
        if len(r) == 0:
            empty_lines += 1
        else:
            empty_lines = 0

def writer0(tty):
    time.sleep(1)
    print ">> +++"
    tty.write("+++")
    await_at_response(tty)

    send_command(tty,"ATND")
    read_nd_response(tty)

    send_command(tty,"ATAI")
    await_at_response(tty)

    send_command(tty,"ATCN")
    await_at_response(tty)


if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-x", "--at_cmd",
                      action="store_true",
                      help="send an AT command sequence")
    (options,args) = parser.parse_args()

    ctl = XBeeController()

    if options.at_cmd:
        writer0(ctl.fh)
    else:
        writer(ctl)
