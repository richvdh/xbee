#!/usr/bin/env python

import optparse
import os
import select
from struct import calcsize,pack,unpack
import sys
import termios
import time


def calc_checksum(frame):
    return 0xFF - (sum([ord(f) for f in frame]) & 0xFF)

def format_bytes(frame):
    """ format bytes as hex string
    """
    return " ".join(("%02x" % ord(b) for b in frame))

class XBeeController(object):
    AT_COMMAND=0x08
    REMOTE_AT_COMMAND = 0x17
    RESPONSE_BIT = 0x80
    AT_COMMAND_RESPONSE = AT_COMMAND + RESPONSE_BIT
    REMOTE_COMMAND_RESPONSE = REMOTE_AT_COMMAND + RESPONSE_BIT

    API_DELIMITER = 0x7E

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

        returns: string
        """

        # await delimiter
        while True:
            ch = self.fh.read(1)
            if ord(ch) == self.API_DELIMITER:
                break
            print "<<< ", ch

        len_bytes = self.fh.read(2)
        length = unpack(">H",len_bytes)
        frame = self.fh.read(length[0])
        cs = self.fh.read(1)

        print "<<<", format_bytes(ch + len_bytes + frame + cs)

        if ord(cs) != calc_checksum(frame):
            raise Exception("mismatched checksum")
        return frame

    def send_frame(self, api_identifier, api_frame):
        """
        send an API frame

        api_identifier: integer api identifier
        api_frame: string of api bytes

        returns: frame number
        """

        frame_no = 1
        frame_len = len(api_frame)+2
        frame = pack(">BHBB", self.API_DELIMITER,
                     frame_len, api_identifier, frame_no) + \
                api_frame
        checksum = calc_checksum(frame[3:])
        frame += chr(checksum)

        print ">>>", format_bytes(frame)

        self.fh.write(frame)
        return frame_no

    def handle_at_response(self, expected_frame_no, multi_response, 
                           remote_command=False):
        response_offset = 2 # frameno, id
        if remote_command:
            expected_response = self.REMOTE_COMMAND_RESPONSE
            response_offset += 8 + 2
        else:
            expected_response = self.AT_COMMAND_RESPONSE

        while True:
            resp=self.read_frame()

            (rx_id, rx_frame_no) = unpack(">BB", resp[0:2])

            if rx_frame_no != expected_frame_no:
                raise Exception("Unexpected seqno %02x" % resp[1])

            if rx_id != expected_response:
                raise Exception("Unexpected response type %02x" % rt)

            (cmdname,rc) = unpack(">2sB", resp[response_offset:
                                               response_offset+3])

            if rc != 0:
                print "<< ERROR %i" % rc
                raise Exception("Error from API command")

            result = resp[response_offset+3:]
            print "<< OK", format_bytes(result)

            if not multi_response:
                yield result
                return

            if len(result) == 0:
                return

            yield result

    def at_command(self, cmd, multi_response=False):
        """send an AT command using the API, and return the result

        cmd: 2-letter AT command

        multi_response: True if command results in multiple responses. In this
          case, response will be a list

        returns: list of result strings
        """

        print ">> %s" % cmd
        frame_no = self.send_frame(self.AT_COMMAND, cmd)
        return self.handle_at_response(frame_no, multi_response)

    def remote_at_command(self, dest, cmd, opts=0, multi_response=False):
        """send a remote AT command, and return the result

        dest: destination address
        cmd: 2-letter AT command
        opts: command options

        multi_response: True if command results in multiple responses. In this
          case, response will be a list

        returns: list of result strings
        """

        print ">> (%x) %s" % (dest, cmd)
        if dest >= 0xFFFF:
            dest_16 = 0xFFFE
            dest_64 = dest
        else:
            dest_64 = 0
            dest_16 = dest
        api_frame = pack(">QHB2s",dest_64,dest_16,opts,cmd)
        frame_no = self.send_frame(self.REMOTE_AT_COMMAND, api_frame)

        return self.handle_at_response(frame_no, multi_response, True)

def send_nd_command(ctl):
    r = ctl.at_command("ND", True)
    for node in r:
        fmt = ">HLLB"
        fmtlen = calcsize(fmt)
        (my,sh,sl,db) = unpack(fmt,node[0:fmtlen])
        ni = node[fmtlen:-1]

        print "MY: %04x" % my
        print "SH: %08x" % sh
        print "SL: %08x" % sl
        print "DB: %02x" % db
        print "NI: %s" % ni
        print

def writer(ctl):
    send_nd_command(ctl)
    print list(ctl.remote_at_command(0x0013a200406899a9,
                                "GT"))

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
