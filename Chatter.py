
"""
Copyright (c) 2014, Patrick Farrell

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted,
provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL,
DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE
OR PERFORMANCE OF THIS SOFTWARE.
"""

# Written by: Patrick Farrell

# The program is a TCP chat app that allows for auto discovery of available clients.

import os
import sys
from Tkinter import *
import time
import Tkconstants, tkFileDialog
import tkMessageBox as box
import threading
import platform
import Queue
import socket
import json

MULTICAST_DISCOVERY_ADDRESS = "238.123.45.67"
MULTICAST_DISCOVERY_PORT = 5768

class MulticastSocketHelper:

	def __init__(self, send_socket):
		print "Constructor"
		self.host_ip = "192.168.1.129"

		if send_socket == True:
			self.mcastsock = self.createMcastSendSocket()
		else:
			# Create a multicast socket on the discovery address and port
			if platform.system() == "Windows":
				self.mcastsock = self.joinMcastSocketWindows(MULTICAST_DISCOVERY_ADDRESS, MULTICAST_DISCOVERY_PORT, self.host_ip, 1)
			else:
				self.mcastsock = self.joinMcastSocket(MULTICAST_DISCOVERY_ADDRESS, MULTICAST_DISCOVERY_PORT, self.host_ip, 1)

	# Get the socket 
	def getSocket(self):
		return self.mcastsock

	def createMcastSendSocket(self):
		  # Create the socket
		  mcastsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		  # Make the socket multicast-aware, and set TTL.
		  mcastsock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20) # Change TTL (=20) to suit

		  return mcastsock

	def joinMcastSocket(self, mcast_addr, port, if_ip, timeout):
		"""
		Returns a live multicast socket
		mcast_addr is a dotted string format of the multicast group
		port is an integer of the UDP port you want to receive
		if_ip is a dotted string format of the IP address on the interface you will use
		"""

		print "Creating Multicast socket for %s:%d for interface IP %s" % (mcast_addr, port, if_ip)
		#create a UDP socket
		mcastsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

		#allow other sockets to bind this port too
		mcastsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

		#explicitly join the multicast group on the interface specified
		mcastsock.setsockopt(socket.SOL_IP,socket.IP_ADD_MEMBERSHIP,
			socket.inet_aton(mcast_addr)+socket.inet_aton(if_ip))

		#Set Socket Timeout
		mcastsock.settimeout(timeout)

		#finally bind the socket to start getting data into your socket
		mcastsock.bind((mcast_addr,port))

		return mcastsock

	def joinMcastSocketWindows(self, mcast_addr, port, if_ip, timeout):
		"""
		Returns a live multicast socket
		mcast_addr is a dotted string format of the multicast group
		port is an integer of the UDP port you want to receive
		if_ip is a dotted string format of the IP address on the interface you will use
		"""

		if if_ip == None:
			print "Error: you must specify an IP address of the adapter you wish to bind on"
			print 'syntax is: "python wrsa_trace.py -l <local_ip_address.>'
			exit(-1)

		#create a UDP socket
		mcastsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

		#bind the socket to start getting data into your socket
		#For some reason on windows you have to bind to the socket differently

		mcastsock.bind(("%s" % if_ip, port))
		mreq = socket.inet_aton(mcast_addr) + socket.inet_aton("%s" % if_ip)
		mcastsock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		#Set Socket Timeout
		mcastsock.settimeout(timeout)

		return mcastsock


class MulticastDiscoverySender:

	"""This class sends out our mulitcast discovery message so other users know that we are online and are available
	to chat.  We send this message out periodically so the other users know that we are still available and online.
	"""

	def __init__(self):
		self.send_stop = False
		self.host_ip = "192.168.1.129"
		self.user_name = "Patrick"

		self.socketHelper = MulticastSocketHelper(send_socket=True)
		self.mcastsock = self.socketHelper.getSocket()

	def sendPeriodicDiscoveryMessageThread(self):
		print "sendPeriodicDiscoveryMessage TODO"
		discovery_message = {}
		discovery_message['name'] = self.user_name
		discovery_message['ip'] = self.host_ip

		discovery_message_json = json.dumps(discovery_message)

		while self.send_stop == False:
			print "sending periodic message"
			self.mcastsock.sendto(discovery_message_json, (MULTICAST_DISCOVERY_ADDRESS, MULTICAST_DISCOVERY_PORT))
			time.sleep(1)

	def stopSending(self):
		print "MulticastDiscoverySender stop"
		self.send_stop = True

class QueueMessage():

	DISCOVERY_MESSAGE = 0

	def __init__(self):
		self.ip = ""
		self.messageType = self.DISCOVERY_MESSAGE
		self.message = ""

	def setClientIP(self, ip):
		self.ip = ip

	def setMessageType(self, msgType):
		self.messageType = msgType

	def setMessage(self, message):
		self.message = message

class MulticastDiscoveryListener:

	"""This class listens on a multicast socket for discovery messages from other Chatter users
	It it detects another Chatter User, it adds that user to the list of available chatter users
	that we can chat with.
	"""

	def __init__(self):

		self.listen_stop = False
		self.socketHelper = MulticastSocketHelper(send_socket=False)
		self.mcastsock = self.socketHelper.getSocket()

	def networkReceiveThread(self, message_queue):

		print "networkRecieve: Waiting for packet"

		while self.listen_stop == False:
			data_length = 0
			try:
				data, addr = self.mcastsock.recvfrom(1024)
				data_length = len(data)
			except KeyboardInterrupt:
				self.stopListen()
			except socket.error, e:
				pass
				#print 'Expection'

			if data_length > 0:
				length_remaining = self.parseDiscoveryPacket(data, addr, message_queue)

	def parseDiscoveryPacket(self, data, addr, message_queue):

		length_parsed = len(data)

		# Add the Message to the Queue so it can be added to the GUI
		# TODO: I don't like that the GUI is going to have to make the decision to display this information.
		#       There should be some layer that makes the decision what to send to the GUI based on what is
		#       being received by the network.

		# Convert the message from the socket to a dictionary
		# TODO: Need to validate that this is a valid JSON structure.
		message = json.loads(data)

		q_message = QueueMessage()
		q_message.setClientIP(addr)
		q_message.setMessage(message['name'])

		message_queue.put(q_message)

		# Return the length of the data that is left to parse
		return (len(data) - length_parsed)

	def stopListen(self):
		print "MulticastDiscoveryListener stop"
		self.listen_stop = True

class Buddy:

	def __init__(self):
		self.name = ""
		self.last_heard = -1
		self.active = False
		self.ip = ""

class BuddyList:

	def __init__(self):
		self.list = []

	# Any time a new buddy discovery message is received, it should pass through this function
	# to see if we already know about this buddy, add them to the buddy list, and update their last heard from time.
	def processBuddyDiscoveryMessage(self, q_message):

		self.addBuddy(q_message.message)

	def addBuddy(self, new_buddy_name):
		# First check if we know about this buddy
		have_buddy = self.checkForBuddy(new_buddy_name)
		new_buddy = Buddy()
		new_buddy.name = new_buddy_name
		new_buddy.active = True

		# If we don't have this buddy in our list, add the buddy
		if have_buddy == False:
			print "Adding new buddy %s to the list" % new_buddy.name
			self.list.append(new_buddy)
		else:
				print "We already have this buddy %s" % new_buddy.name
				pass

	def checkForBuddy(self, new_buddy_name):
		for index, buddy in enumerate(self.list):
			print index, buddy.name

			# We found this buddy in our list
			if buddy.name == new_buddy_name:
				return True

		# We didn't find the buddy in the list
		return False

class GuiPart:

	def __init__(self, master, message_queue, endCommand):

		self.master = master
		self.message_queue = message_queue
		self.stop = False
		self.endCommand = endCommand
		self.buddy_list = BuddyList()

		self.initialize()

	def initialize(self):

		self.master.geometry("450x500")
		# create a menu
		menu = Menu(self.master)
		root.config(menu=menu)

		filemenu = Menu(menu)
		menu.add_cascade(label="File", menu=filemenu)

		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=self.exitCallback)

		helpmenu = Menu(menu)
		menu.add_cascade(label="Help", menu=helpmenu)
		helpmenu.add_command(label="About...", command=self.helpCallback)

		# Message Display Frame
		self.messageDisplayFrame = Frame(self.master, borderwidth=2, relief=GROOVE)
		self.messageDisplayFrame.pack(side=TOP, fill=X)

		self.messageWindow = Text(self.messageDisplayFrame, borderwidth=2, relief=GROOVE)
		self.messageWindow.pack(side=TOP, fill=X)

		# Message Input Frame
		self.messageInputFrame = Frame(self.master, borderwidth=2, relief=GROOVE)
		self.messageInputFrame.pack(side=TOP, fill=X)

		self.message_input = Entry(self.messageInputFrame)
		self.message_input.pack()

		send_button = Button(self.messageInputFrame, text="Send", width=6, command=self.sendCallback)
		send_button.pack(side=LEFT, padx=2, pady=2)

	def processIncoming(self):
		"""
		Handle all the messages currently in the queue (if any).
		"""
		while self.message_queue.qsize():
			try:
				print "got queue message"
				q_message = self.message_queue.get(0)

				# Check if this is a discovery message and if we already know about this buddy.
				buddy_name = q_message.message
				self.buddy_list.processBuddyDiscoveryMessage(q_message)

				if q_message.messageType == 0:
					self.messageWindow.insert(INSERT, q_message.message + "\n")
					self.messageWindow.pack()
			except Queue.Empty:
				pass


	def exitCallback(self):
		if box.askquestion("Question", "Are you sure to quit?") == 'yes':
			print "Ending application"

	def sendCallback(self):
		print "TODO: Implement send callback"
		newMessage = self.message_input.get()

		self.messageWindow.insert(INSERT, newMessage + "\n")
		self.messageWindow.pack()

	def helpCallback(self):
		box.showinfo("Information", "Chatter")

	def exitCallback(self):
		if box.askquestion("Question", "Are you sure to quit?") == 'yes':
			self.stop = True
			self.endCommand()

class ChatterApp:

	START_MULTICAST_DISCOVERY_SENDER_THREAD = True
	START_MULTICAST_DISCOVERY_LISTENER_THREAD = True
	START_TCP_LISTENER_THREAD = False

	def __init__(self, master, *args, **kwargs):
		"""
		Start the GUI and the asynchronous threads. We are in the main
		(original) thread of the application, which will later be used by
		the GUI. We spawn a new thread for the worker.
		"""

		# Create the queue
		self.message_queue = Queue.Queue()

		self.master = master

		# Set up the GUI part
		self.gui = GuiPart(master, self.message_queue, self.endApplication)

		# Start threads to do asynchronous I/O
		if self.START_MULTICAST_DISCOVERY_SENDER_THREAD == True:
			self.mcastDiscoverySender = MulticastDiscoverySender()
			self.mcastSenderThread = threading.Thread(target=self.multicastSenderThread)
			self.mcastSenderThread.start()

		if self.START_MULTICAST_DISCOVERY_LISTENER_THREAD == True:
			self.mcastDiscoveryListener = MulticastDiscoveryListener()
			self.mcastDiscoverThread = threading.Thread(target=self.multicastDiscoveryThread)
			self.mcastDiscoverThread.start()

		if self.START_TCP_LISTENER_THREAD == True:
			self.thread2 = threading.Thread(target=self.tcpListenerThread)
			self.thread2.start()

		# Start the periodic call in the GUI to check if the queue contains
		# anything
		self.running = 1
		self.periodicCall()

	def periodicCall(self):
		"""
		Check every 100 ms if there is something new in the queue.
		"""
		self.gui.processIncoming()

		if not self.running:
			# This is the brutal stop of the system. You may want to do
			# some cleanup before actually shutting it down.
			time.sleep(1)
			sys.exit(1)
		self.master.after(100, self.periodicCall)

	def multicastSenderThread(self):
		"""
		This is where we handle the asynchronous I/O. For example, it may be
		a 'select()'.
		One important thing to remember is that the thread has to yield
		control.
		"""
		self.mcastDiscoverySender.sendPeriodicDiscoveryMessageThread()

	def multicastDiscoveryThread(self):
		"""
		This is where we handle the asynchronous I/O. For example, it may be
		a 'select()'.
		One important thing to remember is that the thread has to yield
		control.
		"""
		self.mcastDiscoveryListener.networkReceiveThread(self.message_queue)

	def tcpListenerThread(self):
		"""
			This thread we listen for incomming connections from other users
		"""
		print "TODO"

	def endApplication(self):
		if self.START_MULTICAST_DISCOVERY_SENDER_THREAD:
			self.mcastDiscoverySender.stopSending()

		if self.START_MULTICAST_DISCOVERY_LISTENER_THREAD:
			self.mcastDiscoveryListener.stopListen()

		self.running = 0
		sys.exit()

if __name__ == '__main__':

	print "Starting Chatter"
	root = Tk()
	root.title("Chatter")

	app = ChatterApp(root)
	root.mainloop()
