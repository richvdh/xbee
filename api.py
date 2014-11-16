#!/usr/bin/env python

import optparse
import os
import select
from struct import pack,unpack
import sys
import termios
import time

class XBeeController(object):
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

    def send_frame(self, api_identifier, frame_no, api_frame):
        """
        send an API frame

        api_identifier: integer api identifier
        frame_no: integer frame number
        api_frame: list of bytes
        """

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

    def api_command(self, api_identifier, api_frame):
        """
        send an api frame, and await the response

        api_identifier: integer api identifier
        api_frame: list of bytes

        returns tuple (response_type,[result_bytes])
        """
        frameno = 1
        self.send_frame(api_identifier, frameno, api_frame)
        resp=self.read_frame()
        
        if resp[1] != frameno:
            raise Exception("Unexpected seqno %02x" % resp[1])

        return (resp[0], resp[2:])

    def at_command(self, cmd):
        """
        send an AT command using the API, and return the result

        returns: integer result, or None on error
        """

        print ">> %s" % cmd
        (rt, rb) = self.api_command(0x08,[ord(cmd[0]),ord(cmd[1])])

        if rt != 0x88:
            raise Exception("Unexpected response type %02x" % rt)

        if rb[2] != 0:
            print "<< ERROR"
            return None

        s = 0
        for b in rb[3:]:
            s <<= 8
            s |= b

        print ">> OK %i" % s
        return s


def writer(ctl):
    r = ctl.at_command("DL")

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
