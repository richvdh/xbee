import logging
import termios
from struct import calcsize, pack, unpack

logger = logging.getLogger(__name__)

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

        self.log_api_frames = True
        self._next_frame_no = 1
        self.on_api_frame = None

    def _frame_no(self):
        n = self._next_frame_no
        self._next_frame_no += 1
        if self._next_frame_no >= 256:
            self._next_frame_no = 1
        return n

    def configure(self):
        flags = termios.tcgetattr(self.fh)

        # flags is [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
        # the following is basically the same as 'raw' mode.

        flags[0] &= ~(termios.IGNBRK | termios.BRKINT) # line breaks read as \0
        flags[0] &= ~(termios.PARMRK) # parity errors read as \0
        flags[0] &= ~(termios.ISTRIP) # don't strip 8th bit
        flags[0] &= ~(termios.INLCR | termios.IGNCR | termios.ICRNL) # don't mess with CR/NL
        flags[0] &= ~(termios.IXON) # ignore XON/XOFF

        flags[1] &= ~(termios.OPOST) # don't do output processing

        # disable most special-character processing
        flags[2] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
                         | termios.IEXTEN)

        # set the line discipline
        flags[3] &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB)
        flags[3] |= termios.CS8

        # disable CTS/RTS for now (we probablyoy ought to be able to make this work?
        flags[2] &= ~termios.CRTSCTS
        flags[4] = termios.B9600 # ispeed
        flags[5] = termios.B9600 # ospeed

        termios.tcsetattr(self.fh, termios.TCSANOW, flags)
        termios.tcsendbreak(self.fh, 0)

    def _read_frame(self):
        """
        wait for an API frame, and read it

        returns: string
        """

        def await_delimiter():
            while True:
                ch = self.fh.read(1)
                if ord(ch) == self.API_DELIMITER:
                    break
                if self.log_api_frames:
                    logger.debug("<<< %s", ord(ch))

        while True:
            await_delimiter()
            len_bytes = self.fh.read(2)
            length = unpack(">H",len_bytes)
            frame = self.fh.read(length[0])
            cs = self.fh.read(1)

            if self.log_api_frames:
                logger.debug("<<< %s", format_bytes(len_bytes + frame + cs))

            if ord(cs) != calc_checksum(frame):
                logger.error("mismatched checksum; ignoring frame")
            else:
                return frame

    def _send_frame(self, api_identifier, api_frame):
        """
        send an API frame

        api_identifier: integer api identifier
        api_frame: string of api bytes

        returns: frame number
        """
        frame_no = self._frame_no()
        frame_len = len(api_frame)+2
        frame = pack(">BHBB", self.API_DELIMITER,
                     frame_len, api_identifier, frame_no) + \
                api_frame
        checksum = calc_checksum(frame[3:])
        frame += chr(checksum)

        if self.log_api_frames:
            logger.info(">>> %s", format_bytes(frame))

        self.fh.write(frame)
        return frame_no

    def _dispatch_rx_io(self, address_bytes, cmd_data):
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
            logger.info("address: %x, strength %d, sample data: %r",
                        address, rssi, sample)
            if self.on_api_frame:
                self.on_api_frame(address, rssi, sample)

    def _dispatch_frame(self, frame):
        """Dispatch a received frame to relevant handlers"""
        rx_id = ord(frame[0])
        if rx_id == self.RX_IO_64:
            self._dispatch_rx_io(8, frame[1:])
        elif rx_id == self.RX_IO_16:
            self._dispatch_rx_io(2, frame[1:])
        else:
            logger.info("ignoring unhandled msg %02x", rx_id)

    def _await_at_response(self, expected_frame_no, multi_response,
                           remote_command=False):
        if remote_command:
            expected_response = self.REMOTE_COMMAND_RESPONSE
        else:
            expected_response = self.AT_COMMAND_RESPONSE

        while True:
            resp=self._read_frame()

            (rx_id, rx_frame_no) = unpack(">BB", resp[0:2])

            if rx_frame_no != expected_frame_no:
                self._dispatch_frame(resp)
                continue

            if rx_id != expected_response:
                raise Exception("Unexpected response type %02x" % rx_id)

            if remote_command:
                (addr64, addr16) = unpack(">QH", resp[2:12])
                response_offset = 12
            else:
                response_offset = 2

            (cmdname, rc) = unpack(">2sB", resp[response_offset:
                                                response_offset+3])

            result = resp[response_offset+3:]

            if rc == 0:
                rc_str = "OK"
            elif rc == 1:
                rc_str = "Error"
            elif rc == 2:
                rc_str = "Invalid command"
            elif rc == 3:
                rc_str = "Invalid Parameter"
            elif rc == 4:
                rc_str = "No response"
            else:
                rc_str = "[unknown error code]"
            msg = "%s: %i(%s) %s" % (cmdname, rc, rc_str,
                                     format_bytes(result))
            if remote_command:
                logger.info("<< (%x/%x) %s",
                            addr64, addr16, msg)
            else:
                logger.info("<< %s", msg)

            if rc != 0:
                raise Exception("Error from API command")

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

        logger.info(">> %s %s", cmd, "" if arg_val is None else arg_val)
        arg_string = format_arg_val(arg_val)
        frame_no = self._send_frame(self.AT_COMMAND, cmd+arg_string)
        return list(self._await_at_response(frame_no, multi_response))

    def transmit_64(self, dest, data):
        """send data to a remote node

        :param dest: destination address
        :param data: raw data to send
        """

        print ">> (%x) %s" % (dest, data)
        api_frame = pack(">QB",dest,0)+data
        frame_no = self._send_frame(self.TX_REQUEST_64,api_frame)
        # todo: handle unexpected responses
        self._read_frame()

    def transmit_16(self, dest, data):
        """send data to a remote node

        :param dest: destination address
        :param data: raw data to send
        """

        print ">> (%x) %s" % (dest, data)
        api_frame = pack(">HB",dest,0)+data
        frame_no = self._send_frame(self.TX_REQUEST_16,api_frame)
        # todo: handle unexpected responses
        self._read_frame()

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
        frame_no = self._send_frame(self.REMOTE_AT_COMMAND, api_frame)

        return list(self._await_at_response(frame_no, multi_response, True))

    def receive(self):
        """Receive, decode and dispatch a single API frame"""
        resp=self._read_frame()
        self._dispatch_frame(resp)
