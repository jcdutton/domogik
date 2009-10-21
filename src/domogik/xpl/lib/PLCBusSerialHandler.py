#!/usr/bin/python
# -*- coding: utf-8 -*-                                                                           

""" This file is part of B{Domogik} project (U{http://www.domogik.org}).

License
=======

B{Domogik} is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

B{Domogik} is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Domogik. If not, see U{http://www.gnu.org/licenses}.

Module purpose
==============

Get event from PLCBUS and send them on xPL

Implements
==========

- serialHandler

@author: Yoann HINARD <yoann.hinard@gmail.com>
@copyright: (C) 2007-2009 Domogik project
@license: GPL(v3)
@organization: Domogik
"""

import sys
import time
from binascii import hexlify
import Queue
import threading
import mutex
import datetime
import serial



class serialHandler():
    """
    Threaded class to handle serial port in PLCbus communication
    Send PLCBUS frames when available in the send_queue and manage
    retransmission if needed
    Put received frames in the receveive_queue (to be sent on the xPL network
    """

    def __init__(self, serial_port_no, command_cb, message_cb):
        """ Initialize threaded PLCBUS manager
        Will handle communication to and from PLCBus 
        @param serial_port_no : Number or path of the serial port 
        @param command_cb: callback called when a command has been succesfully sent
        @param message_cb: called when a message is received from somewhere else on the network
        For these 2 callbacks, the param is sent as an array
        """
        #invoke constructor of parent class
        self._ack = [] #Shared list between reader and writer
        self._need_answer = ["1D", "1C"]
        self._stop = threading.Event()
        self._has_message_to_send = threading.Event()
        #serial port init
        self.__myser = serial.Serial(serial_port_no, 9600, timeout=0.4,
                parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                xonxoff=0) #, rtscts=1)
        self._want_lock = threading.Event()
        self._mutex = mutex.mutex()
        self._writer = self.__Writer(self.__myser, self._want_lock, self._mutex, self._ack, command_cb)
        self._reader = self.__Reader(self.__myser, self._want_lock, self._mutex, self._ack, message_cb)
        self._writer.start()
        self._reader.start()

    def add_to_send_queue(self, frame):
        """ Add a frame to the send queue
        """
        self._writer.add_to_send_queue(frame)

    def stop(self):
        """Ask reader/writer to leave
        """
        self._reader.stop()
        self._writer.stop()

    class __Writer(threading.Thread):
        """Threaded writer
        """

        def __init__(self, serial, lock, mutex, ack_queue, command_callback):
            """ Internal threaded class
            Manage write to serial port
            @param serial : serial object
            @param lock : threading.Event object shared with reader
            @param mutex : mutex object shared with reader
            @param ack_queue : Queue for ack messages shared with Reader
            """
            threading.Thread.__init__(self)
            self.__myser = serial
            self._has_message_to_send = lock
            self._mutex = mutex
            self._ack = ack_queue
            self._send_queue = Queue.Queue()
            self._stop = threading.Event()
            self._cb = command_callback

        def _send(self, plcbus_frame):
            #seems to work OK, but is all this retransmission process needed ?
            #frame should already be properly formated.
            self._mutex.lock(self._basic_write, plcbus_frame)
            self._has_message_to_send.clear()
            self._has_message_to_send.wait()
#                time.sleep(0.4)
            #print 'sent 2 times'
            #Resend if proper ACK not received
            #check for ack pulse
            if (int(plcbus_frame[8:10], 16) >> 5) & 1: #ACK pulse bit set to 1
                #The ACK message take only 10ms + 10ms to bring it back to the computer.
                #Anyway, it seems that the mean time before reading the ack is about 
                #0.6s . Because there is another sleep in the loop, this sleep is only 0.3s
                time.sleep(0.3)
                ACK_received = 0
                # like a timer, does not wait for more than 2seconds for example
                time1 = time.time()
                # print "time1", time1
                while 1:
                    time2 = time.time()
                    while 1:
                      #  message=self.__myser.read(size=9) #timeout is 400ms
                        #The ack message is sent immediately after the message has been received 
                        #and transmission time is 20mS (10ms for message propagation to adapter,
                        #and 10ms between adapter and computer
                        #We sleep 20ms between each check
                        time.sleep(0.3)
                        if self._has_ack_received(plcbus_frame.decode('HEX')):
                            ACK_received=1
                            self._cb(self.explicit_message(plcbus_frame))
                        
                        #We check up to 3 times (3*0.3s) if a ack has been received 
                        #before resending it once.
                        if (time2 + 0.9 < time.time()):
                            break #200ms

                    #We resend the message up to 3 times (max 1.8s for global timeout)
                    if(ACK_received==0):
                        self._mutex.lock(self._basic_write, plcbus_frame)
                        self._has_message_to_send.clear()
                        self._has_message_to_send.wait()

                    if(ACK_received==1 or time1 + 2.7 < time.time()):
                        break #2s
            else:
                #No ACK asked, we consider that the message has been correctly sent
                self._cb(self.explicit_message(plcbus_frame))


        def stop(self):
            self._stop.set()
            self.__myser.close()

        def _has_ack_received(self, message):
            """ Check if an ack has been received for a message 
            Remove the ack from list if there is one received
            @param check ack against this message
            """
            for ack in self._ack:
                if self._is_ack_for_message(ack, hexlify(message)):
                    self._ack.remove(ack)
                    return True
            return False

        def _is_ack_for_message(self, m1, m2):
            #check the ACK bit
            #print "ACK check " + m1.encode('HEX') +" " + m2
            #check house code and user code in hexa string format like '45E0'
            if(m1[4:8].upper()==m2[4:8].upper()): #Compare user code + home unit
                #print "housecode and usercode OK"
                return (int(m1[14:16], 16) & 0x20) #test only one bit
            return False

        
        def _basic_write(self, frame):
            """Write a frame on serial port
            This method should only be called as mutex.lock() parameter
            @param frame : The frame to write 
            """
            self.__myser.write(frame.decode("HEX"))

        def _flush_queue(self):
            """Send all frame in the queue
            """
            while not self._send_queue.empty():
                self._send(self._send_queue.get_nowait())

        def add_to_send_queue(self, trame):
            self._send_queue.put(trame)
            self._has_message_to_send.set()

        def explicit_message(self, message):
            """ Parse a frame 
            """
            r = {}
            r["start_bit"] = message[0:2]
            r["data_length"] = int(message[2:4])
            int_length = int(message[2:4])*2
            r["data"] = message[4:5+int_length]
            r["d_user_code"] = r["data"][0:2]
            r["d_home_unit"] = r["data"][2:4]
            r["d_command"] = r["data"][4:6]
            r["d_data1"] = r["data"][6:8]
            r["d_data2"] = r["data"][8:10]
            if r["data_length"] == 6:
                r["rx_tw_switch"] = r["data"][11:]
            r["end_bit"] = message[-2:]
            return r

        def run(self):
            """ Start writer thread 
            """
            while not self._stop.isSet():
                if not self._send_queue.empty():
                    self._flush_queue()



    class __Reader(threading.Thread):
        """Threaded reader
        """

        def __init__(self, serial, lock, mutex, ack_queue, message_cb):
            """ Internal threaded class
            Manage read from serial port
            @param serial : serial object
            @param lock : threading.Event object shared with writer
            @param mutex : mutex object shared with writer
            @param ack_queue : Queue object shared with Writer to store ack
            """
            threading.Thread.__init__(self)
            self.__myser = serial
            self._has_message_to_send = lock
            self._mutex = mutex
            self._ack = ack_queue
            self._receive_queue = Queue.Queue()
            self._answer_queue = Queue.Queue()
            self._stop = threading.Event()
            self._cb = message_cb

        def _is_answer(self, message):
            # if command is in answer required list (not ACK required, it's
            # different)
            # if R_ID_SW bit set
            # maybe pass this list to the _init_ of this handler to make it
            # compatible with other protocols
            if((int(message[14:15], 16) >> 2 & 1) and message[8:10].upper() in
                    self._need_answer):
                return True
            return False

        def explicit_message(self, message):
            """ Parse a frame 
            """
            r = {}
            r["start_bit"] = message[0:2]
            r["data_length"] = int(message[2:4])
            int_length = int(message[2:4])*2
            r["data"] = message[4:5+int_length]
            r["d_user_code"] = r["data"][0:2]
            r["d_home_unit"] = r["data"][2:4]
            r["d_command"] = r["data"][4:6]
            r["d_data1"] = r["data"][6:8]
            r["d_data2"] = r["data"][8:10]
            if r["data_length"] == 6:
                r["rx_tw_switch"] = r["data"][11:]
            r["end_bit"] = message[-2:]
            return r

        def receive(self):
            #not tested
            message=self.__myser.read(9)
            #put frame_PLCbus in receivedqueue
            if(message):
                m_string=hexlify(message)
                #self.explicit_message(m_string)
                #if message is likely to be an answer, put it in the right queue
                #First we check that the message is not from the adapter itself
                #And simply ignore it if it's the case 
                if self._is_from_myself(m_string):
                    return
                if self._is_answer(m_string):
                    self._answer_queue.put(m_string)
                elif self._is_ack(m_string):
                    self._ack.append(m_string)
                else:
                    self._cb(self.explicit_message(m_string))

        def stop(self):
            """ Ask the thread to stop, 
            will only set a threading.Event instance
            and close serial port
            """
            self._stop.set()
            self.__myser.close()

        def run(self):
            #serial handler main thread
            self._mutex.testandset()
            while not self._stop.isSet():
                #The Event _has_message_to_send is only used to optimize
                #The test isSet is much faster than the empty() test 
                if not self._has_message_to_send.isSet():
                    #If _has_message_to_send is locked, then there is at least 1 lock(function)
                    #in the queue, so the unlock() will just do this call, 
                    #not really unlock the mutex.
                    self._mutex.unlock()
                    self._mutex.testandset()
                    self._has_message_to_send.set()
                #print "receiving"
                self.receive()

        def _is_ack(self, message):
            """ Check if a message is an ack 
                @param message : message to check
            """
            return int(message[14:16], 16) & 0x20

        def _is_from_myself(self, message):
            """ Check if a message is sent by the adapter itself
                @param message : message to check
            """
            return int(message[14:16], 16) & 0x10

        def get_from_receive_queue(self):
            trame=self._receive_queue.get_nowait()
            return trame

        def get_from_answer_queue(self):
            trame = self._answer_queue.get(True, 2) #do not wait for more than 2s
            return trame

#a=serialHandler()
#a.start()
#pas sur du contenu des trames suivantes
#trame='0205000000000003'
#trame='0205000102000003'#A2 on
#trame='0205000002000003'#A1 on
#trame='0205450122000003' #A2 on ack asked
#trame='020545E302000003' #B1 on
#a.add_to_send_queue(trame)

#a.get_from_receive_queue() #attention, bloquant


#je n'ai pas gere comment quitter
#a.join()



#trame='0205FF0123000003' #A2 off ack asked
#trame='020500000F000003' #Status checking
#trame='0205000018000003' #get signal strength
