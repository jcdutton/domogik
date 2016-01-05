# -*- coding: utf-8 -*-
"""
Velbus domogik plugin
"""

import serial
import socket
import traceback
import threading
from Queue import Queue


class VelbusException(Exception):
    """
    Velbus exception
    """

    def __init__(self, value):
        Exception.__init__(self)
        self.value = value

    def __str__(self):
        return repr(self.value)


class VelbusDev:
    """
    Velbus domogik plugin
    """
    def __init__(self, log, cb_send_xpl, cb_send_trig, stop):
        """ Init object
            @param log : log instance
            @param cb_send_xpl : callback
            @param cb_send_trig : callback
            @param stop : 
        """
        self._log = log
        self._callback = cb_send_xpl
        self._cb_send_trig = cb_send_trig
        self._stop = stop
        self._dev = None
        self._devtype = 'serial'
        self._nodes = {}
	self._log.debug("velbus lib ver 5")
        # Queue for writing packets to Rfxcom
        self.write_rfx = Queue()

        # Thread to process queue
        write_process = threading.Thread(None,
                                         self.write_daemon,
                                         "write_packets_process",
                                         (),
                                         {})
        write_process.start()

    def force_leave(self):
        """ force_leave
        """
        self.log.info("velbus force_leave lib called")

    def open(self, device, devicetype):
        """ Open (opens the device once)
	    @param device : the device string to open
        """
        self._devtype = devicetype
        try:
            self._log.info("Try to open VELBUS: %s" % device)
            if devicetype == 'socket':
                addr = device.split(':')
                addr = (addr[0], int(addr[1]))
                self._dev = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._dev.connect( addr )
            else:
                self._dev = serial.Serial(device, 9600, timeout=0)
		self._dev.timeout = None
            self._log.info("VELBUS opened")
        except:
            error = "Error while opening Velbus : %s. Check if it is the good device or if you have the good permissions on it." % device
            raise VelbusException(error)

    def close(self):
        """ Close the open device
        """
        self._log.info("Close VELBUS lib")
        try:
            self._dev.close()
        except:
            error = "Error while closing device"
            raise VelbusException(error)
       
    def scan(self):
        self._log.info("Starting the bus scan")
        #for add in range(0,0):
        #    self.send_moduletyperequest(add)
        self._log.info("Bus scan finished")
 
    def send_shutterup(self, device):
        """ Send shutter up message
        """
        self._log.info("send_shutterup")
        #data = chr(0x05) + self._blinchannel_to_byte(channel) + chr(0x00) + chr(0x00) + chr(0x00)
        #self.write_packet(address, data)

    def send_temp(self, address):
        """ Send shutter up message
        """
        self._log.info("send_temp")
        #print("send_temp")
        cmd = "03"
        data = address
        self.write_packet(cmd, data)
	return
    
    def send_shutterdown(self, dev):
        self._log.debug("send_shutterdown")
        #data = chr(0x06) + self._blinchannel_to_byte(channel) + chr(0x00) + chr(0x00) + chr(0x00)
        #self.write_packet(address, data)
	return

    def send_level(self, address, level):
        """ Set the level for a device
            if relay => level can only be 0 or 100
            if dimmer => level can be anything from 0 to 100
        """
        self._log.info("send_level")
        cmd = "04"
	level_int = int(level)
        data = "%02s%04X" % (address, level_int)
        self.write_packet(cmd, data)
        return 
        
    def send_moduletyperequest(self, address):
        """ Request module type
        """
        self.write_packet(address, None)

    def write_packet(self, address, data):
        """ put a packet in the write queu
        """
        self._log.info("write packet %s:%s", address, data)
        self.write_rfx.put_nowait( {"address": address,
				"data": data}) 

    def write_daemon(self):
        """ handle the queu
        """
        self._log.info("write deamon")
	self._log.debug("velbus lib write deamon ver 5")
        while not self._stop.isSet():
            res = self.write_rfx.get(block = True)
            self._log.debug("write_daemon here1")
            addr1 = res["address"]
            self._log.debug("write_daemon here2")
            if addr1 == None:
                self._log.debug("address empty")
            else:
                self._log.debug("address added %s", addr1)
            self._log.debug("write_daemon here3")
            data1 = res["data"]
            if data1 == None:
                self._log.debug("data empty")
            else:
                self._log.debug("data added %s", data1)
            self._log.debug("write_daemon here4")
            self._log.debug("Get from Queue : %s > %s" % (addr1, data1))
            self._log.debug("about to send packet")
            if self._devtype == 'socket':
                self._log.debug("packet to socket")
                self._dev.send( packet )
            else:
		write1 = "%s%s\n" % (addr1, data1)
                self._log.debug("packet to serial %s", write1)
                self._dev.write( write1 )
            self._log.debug("sent packet")
            self._stop.wait(0.06)
 
    def listen(self, stop):
        """ Listen thread for incomming VELBUS messages
        """
        self._log.info("Start listening VELBUS")
        # infinite
        try:
            while not stop.isSet():
                self.read()
        except:
            error = "Error while reading velbus device (disconnected ?) : %s" % traceback.format_exc()
            print(error)
            self._log.error(error)
            return

    def read(self):
        """ Read data from the velbus line
        """
        if self._devtype == 'socket':
            data = self._dev.recv(9999)
        else:
            data = self._dev.readline(9999)

        if len(data) >= 2:
            self._log.debug("read packet len %d" % len(data))
            # if ord(data[0]) == 0x00:
            # size = ord(data[3]) & 0x0F
            size = 2
            self._parser(data)

    def _checksum(self, data):
        """
           Calculate the velbus checksum
        """
        assert isinstance(data, str)
        __checksum = 0
        for data_byte in data:
            __checksum += ord(data_byte)
        __checksum = -(__checksum % 256) + 256
        try:
            __checksum = chr(__checksum)
        except ValueError:
            __checksum = chr(0) 
        return __checksum

    def _parser(self, data):
        """
           parse the velbus packet
        """
        assert isinstance(data, str)
        assert len(data) > 0
        assert len(data) >= 2
        # assert ord(data[0]) == 0x0f
        # self._log.debug("starting parser: %s" % data.encode('hex'))
        self._log.debug("starting parser: %s" % data)
	offset = 0
	try:
	    mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
	except:
	    mtype = 255
        self._log.debug("Received message with type: %x" % mtype )
        # first try the module specifick parser
        parsed = False
        try:
            methodcall = getattr(self, "_process_{0}".format(mtype))
            methodcall( data )
            parsed = True
        except AttributeError:
            self._log.debug("Messagetype module specific parser not implemented")	
        else:
            self._log.warning("Received message with unknown type {0}", mtype)

# procee the velbus received messages
# format will beL
#   _process_<messageId> => general parser for this messagetype
#   _process_<messageId>_<moduleType> => parser specifickly for this module type
    def _process_255(self, data):
        """
           Process a 255 Message
           Node type => send out as answer on a module_type_request
        """
        self._log.info("Unknown message 255")

    def _process_0(self, data):
        """
           Process a 0 Message
        """
        self._log.debug("process_0 called")	
        offset = 2
        ver = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        self._log.debug("mtype = 0, ver = %d", ver)	

    def _process_1(self, data):
        """
           Process a 1 Message: Information/Log message.
        """
        offset = 0
        mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        data1 = data[2:]
        self._log.debug("process_1 called")	
        self._log.debug("mtype = %x, string = %s", mtype, data1)	

    def _process_2(self, data):
        """
           Process a 1 Message: Information/Log message.
        """
        offset = 0
        mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        data1 = data[2:]
        self._log.debug("process_2 called")	
        self._log.debug("mtype = %x, Temp Sensor ID = %s", mtype, data1)	

    def _process_3(self, data):
        """
           Process a 3 message Temperature Sensor Temperature
           Resolution: 0.0625 degree celcius
        """
        self._log.debug("process_3 called")	
        offset = 0
        mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        address = data[2:18]
	temp_string = data[18:22]
	try:
		temp_data = int(temp_string, 16)
	except:
		return
        self._log.debug("mtype = %x, Temp Sensor ID = %s, Temp data = %s", mtype, address, temp_string)
        temp = float(temp_data)	/ 16
	temp = (round(temp * 10)) / 10
        self._log.debug("mtype = %x, Temp Sensor ID = %s, Temp = %f", mtype, address, temp)
        self._callback("sensor.basic",
               {"device": address, "type": "temp", "units": "c",
               "current": str(temp) })

    def _process_4(self, data):
        """
           Process a 4 message Valiable setting
        """
        self._log.debug("process_4 called")	
        offset = 0
        mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        address = data[2:4]
	level_hex = data[4:8]
	level_data = int(level_hex, 16)
	level_float = level_data
	level_data = int(level_float)
        self._log.debug("mtype = %x, Level ID = %s, Level data = %d", mtype, address, level_data)
        self._callback("lighting.device",
               {"device": address,
               "level": str(level_data) })

    def _process_5(self, data):
        """
           Process a 5 message On/Off status
        """
        self._log.debug("process_5 called")	
        offset = 0
        mtype = (int(data[offset], 16) << 4) + int(data[offset+1], 16)
        address = data[2:4]
	level_hex = data[4:6]
	level_data = int(level_hex, 16)
	level_string = ""
	if level_data == 0:
		level_string = "OFF"
	if level_data == 1:
		level_string = "ON"
        self._log.debug("mtype = %x, Relay ID = %s, Relay state = %s", mtype, address, level_string)
        self._callback("sensor.basic",
               {"device": address, "type" : "input",
               "current": level_string })

# Some convert procs
    def _channels_to_byte(self, chan):
        """
           Convert a channel to a byte
           only works for one channel at a time
        """
        return chr( (1 << (int(chan) -1)) )

    def _byte_to_channels(self, byte):
        """
           Convert a byte to a channel list
        """
        assert isinstance(byte, str)
        assert len(byte) == 1
        byte = ord(byte)
        result = []
        for offset in range(0, 8):
            if byte & (1 << offset):
                result.append(offset+1)
        return result

    def _blinchannel_to_byte(self, channel):
        """
           Convert a channel 1 or 2 to its correct byte
        """
        assert isinstance(channel, int)
        if channel == 1:
            return chr(0x03)
        else:
            return chr(0x0C)

    def _byte_to_blindchannel(self, byte):
        """
           Convert a byte to its channel
        """
        if byte == chr(0x03):
            return 1
        else:
            return 2


