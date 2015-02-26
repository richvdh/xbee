#!/usr/bin/env python

import optparse
import select
import sys
import time


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
