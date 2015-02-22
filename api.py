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

def format_arg_val(val):
    """ format integer argument into byte string
    """
    if val is None:
        return ""
    if val < 0x10000:
        return pack(">H", val)
    if val < 0x100000000:
        return pack(">L", val)
    return pack(">Q", val)

class XBeeController(object):
    TX_REQUEST_64 = 0x00
    TX_REQUEST_16 = 0x01
    AT_COMMAND = 0x08
    REMOTE_AT_COMMAND = 0x17
    RESPONSE_BIT = 0x80
    RX_PACKET_64 = 0x80
    RX_PACKET_16 = 0x81
    RX_IO_64 = 0x82
    RX_IO_16 = 0x83
    AT_COMMAND_RESPONSE = AT_COMMAND + RESPONSE_BIT
    REMOTE_COMMAND_RESPONSE = REMOTE_AT_COMMAND + RESPONSE_BIT

    API_DELIMITER = 0x7E

    def __init__(self, dev="/dev/ttyS1"):
        self.fh=open('/dev/ttyS1','rw+',0)
        self.configure()

        self.dump_api_frames = True#False

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
            if self.dump_api_frames:
                print "<<< ", ord(ch)

        len_bytes = self.fh.read(2)
        length = unpack(">H",len_bytes)
        frame = self.fh.read(length[0])
        cs = self.fh.read(1)

        if self.dump_api_frames:
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

        if self.dump_api_frames:
            print ">>>", format_bytes(frame)

        self.fh.write(frame)
        return frame_no

    def receive(self):
        """Receive and decode an API frame"""
        
        resp=self.read_frame()

        rx_id = ord(resp[0])

        if rx_id == self.RX_IO_64:
            self.handle_rx_io(8, resp[1:])
        elif rx_id == self.RX_IO_16:
            self.handle_rx_io(2, resp[1:])
        else:
            print "msg %02x" % rx_id

    def handle_rx_io(self, address_bytes, cmd_data):
        """Called to handle an rx_io frame

        :param address_bytes: number of bytes of source address (either 2 or 8)
        """
        def decode_io_sample(active, iodata, offset):
            """decode a single IO sample

            :param active: bitmap of active channels
            :param iodata: data array
            :param offset: inital offset into data array

            :returns (sample, new offset)
            """
            if (active & 0x1FF) != 0:
                # some DIO lines are enabled - DIO data is present
                (dio,) = unpack(">H", iodata[offset:offset+2])
                offset += 2
            else:
                dio = None

            adc=[]
            for chan in range(0,6):
                if (active & 1 << chan+9):
                    # this channel is present
                    (s,) = unpack(">H", iodata[offset:offset+2])
                    offset += 2
                else:
                    s = None
                adc.append(s)

            return ({
                'dio': dio,
                'adc': adc,
            }, offset)


        (address, rssi, opts) = unpack(
            ">HBB" if address_bytes == 2 else ">QBB", 
            cmd_data[0:address_bytes+2])

        iodata=cmd_data[address_bytes+2:]

        # see "I/O data format", p.15, XBee product manual chapter 2
        (nsamples, active) = unpack(">BH", iodata[0:3])

        offset = 3
        for i in range(0,nsamples):
            (sample, offset) = decode_io_sample(active, iodata, offset)
            print "address: %x, strength %d, sample data: %r" % (
                address, rssi, sample)

                


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
                raise Exception("Unexpected seqno %02x" % rx_frame_no)

            if rx_id != expected_response:
                raise Exception("Unexpected response type %02x" % rx_id)

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

    def at_command(self, cmd, arg_val=None, multi_response=False):
        """send an AT command using the API, and return the result

        cmd: 2-letter AT command

        multi_response: True if command results in multiple responses. In this
          case, response will be a list

        returns: list of result strings
        """

        print ">>", cmd, "" if arg_val is None else arg_val
        arg_string = format_arg_val(arg_val)
        frame_no = self.send_frame(self.AT_COMMAND, cmd+arg_string)
        return list(self.handle_at_response(frame_no, multi_response))

    def transmit_64(self, dest, data):
        """send data to a remote node

        :param dest: destination address
        :param data: raw data to send
        """

        print ">> (%x) %s" % (dest, data)
        api_frame = pack(">QB",dest,0)+data
        frame_no = self.send_frame(self.TX_REQUEST_64,api_frame)
        self.read_frame()

    def transmit_16(self, dest, data):
        """send data to a remote node

        :param dest: destination address
        :param data: raw data to send
        """

        print ">> (%x) %s" % (dest, data)
        api_frame = pack(">HB",dest,0)+data
        frame_no = self.send_frame(self.TX_REQUEST_16,api_frame)
        self.read_frame()


    def remote_at_command(self, dest, cmd, arg_val=None, opts=0,
                          multi_response=False):
        """send a remote AT command, and return the result

        dest: destination address
        cmd: 2-letter AT command
        opts: command options

        multi_response: True if command results in multiple responses. In this
          case, response will be a list

        returns: list of result strings
        """

        print ">> (%x)" % dest, cmd, "" if arg_val is None else arg_val
        arg_string = format_arg_val(arg_val)
        if dest >= 0xFFFF:
            dest_16 = 0xFFFE
            dest_64 = dest
        else:
            dest_64 = 0
            dest_16 = dest
        api_frame = pack(">QHB",dest_64,dest_16,opts)+cmd+arg_string
        frame_no = self.send_frame(self.REMOTE_AT_COMMAND, api_frame)

        return list(self.handle_at_response(frame_no, multi_response, True))

def send_nd_command(ctl):
    r = ctl.at_command("ND", multi_response=True)
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

node_1 = 0x0013a200406899a9

def writer(ctl):
    #send_nd_command(ctl)
    #ctl.at_command("SP")
    ctl.transmit_16(0x101, "abc")
    #ctl.transmit_64(node_1, "abc")

    #ctl.remote_at_command(node_1, "GT", arg_val=1000)
    #ctl.remote_at_command(node_1, "IS")
    #ctl.remote_at_command(node_1, "ST")
    #ctl.remote_at_command(node_1, "SP")
    #ctl.remote_at_command(node_1, "AC")
    #ctl.remote_at_command(node_1, "WR")


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
#    parser.add_option("-x", "--at_cmd",
#                      action="store_true",
#                      help="send an AT command sequence")
    (options,args) = parser.parse_args()

    ctl = XBeeController()

    while True:
        ctl.receive()
