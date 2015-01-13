
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
import signal
import socket
import json

# Local Files
from ChatterMessage import *

HAVE_NETIFACES = False

try:
	import netifaces
	HAVE_NETIFACES = True
except ImportError:
	print "Warning: The netifaces module is recommended to run this program."


MULTICAST_DISCOVERY_ADDRESS = "238.123.45.67"
MULTICAST_DISCOVERY_PORT = 5768


def getMyIPAddress():

	#socket.gethostbyname(socket.gethostname())

	if HAVE_NETIFACES:
		# TODO: Make this generic for different interfaces, run on linux to make sure it works for both eth and wifi devices.
		dev = "en0"
		addrs = netifaces.ifaddresses(dev)

	try:
		ipaddrs = addrs[netifaces.AF_INET]
		host_ip = ipaddrs[0].get('addr')
	except:
		host_ip = "127.0.0.1"
		print "Please specify IP Address here, using Host IP = %s" % host_ip

	return host_ip

class TCPSocketHelper:

	def __init__(self):
		print "TCPSocketHelper constructor"

	def createTCPSocket(self):

		print "createTCPSocket"
		#TODO Create 
		# Create a TCP/IP socket
		tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		host_ip = getMyIPAddress()

		# Bind the socket to the port
		server_address = (host_ip, 10000)
		print >>sys.stderr, 'starting up on %s port %s' % server_address
		tcpsock.bind(server_address)

		return tcpsock

class MulticastSocketHelper:

	def __init__(self, send_socket):
		print "Constructor"
		self.host_ip = getMyIPAddress()

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
		self.host_ip = getMyIPAddress()
		self.user_name = "John"

		self.socketHelper = MulticastSocketHelper(send_socket=True)
		self.mcastsock = self.socketHelper.getSocket()

	def setUsername(self, newUsername):
		self.user_name = newUsername

	def sendPeriodicDiscoveryMessageThread(self):
		"""The period messages are sent out as JSON objects with the username, IP address of the source
		TODO: Should add a message version so it is upgradable."""

		print "sendPeriodicDiscoveryMessage TODO"
		discovery_message_json = ChatterMessage.createDiscoveryMessage(self.user_name, self.host_ip)

		while self.send_stop == False:
			#print "sending periodic message"
			self.mcastsock.sendto(discovery_message_json, (MULTICAST_DISCOVERY_ADDRESS, MULTICAST_DISCOVERY_PORT))
			time.sleep(1)

	def stopSending(self):
		print "MulticastDiscoverySender stop"
		self.send_stop = True

class QueueMessage():

	DISCOVERY_MESSAGE = 0
	INCOMING_MESSAGE = 1
	OUTGOING_MESSAGE = 2

	def __init__(self):
		self.ip = ""
		self.username = ""
		self.messageType = self.DISCOVERY_MESSAGE
		self.message = ""

	def setClientIP(self, ip):
		self.ip = ip

	def setMessageType(self, msgType):
		self.messageType = msgType

	def setUserName(self, username):
		self.username = username

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

		self.host_ip = getMyIPAddress()

	def networkReceiveThread(self, message_queue):

		print "networkRecieve: Waiting for packet"

		while self.listen_stop == False:
			data_length = 0
			try:
				data, addr = self.mcastsock.recvfrom(1024)
				data_length = len(data)

				# Check to make sure the packet didn't come from ourself first, if so, drop it.
				if addr[0] == self.host_ip:
					continue

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

		if len(data) > 0:
			# If the message we received is JSON, decode the message and send it up to the GUI.
			try:
				message = ChatterMessage.parseDiscoveryMessage(data)

				# TODO: We should check the message type here and only pass up discovery messages
				q_message = QueueMessage()
				q_message.setClientIP(addr)
				q_message.setMessage(message['name'])

				# Send the newly received discovery packet to the GUI
				message_queue.put(q_message)
			except:
				print "Error: Message received was not JSON"

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

	def getName(self):
		return self.name

	def getIPAddress(self):
		return self.ip

	def updateLastHeardTime(self):
		self.last_heard = time.time()

	def isActive(self):
		return self.active

	def setInactive(self):
		self.active = False

	def setActive(self):
		self.active = True

	def getTimeSinceHeard(self):
		timeNow = time.time()
		timeElapsed = timeNow - self.last_heard

		return timeElapsed


class BuddyList:

	# TODO: Need a thread that goes over the buddy list and checks the last heard from time to the current
	#       time and drops buddys off the list or adds them to an inactive list.

	def __init__(self):
		self.list = []
		self.buddyTimeout = 3  #seconds since we last heard from a buddy before we set them inactive

	# Any time a new buddy discovery message is received, it should pass through this function
	# to see if we already know about this buddy, add them to the buddy list, and update their last heard from time.
	def processBuddyDiscoveryMessage(self, q_message):

		return self.addBuddy(q_message)

	def addBuddy(self, buddy_q_message):
		# First check if we know about this buddy
		new_buddy_name = buddy_q_message.message
		have_buddy = self.checkForBuddy(new_buddy_name)

		new_buddy = Buddy()
		new_buddy.name = new_buddy_name
		new_buddy.ip = buddy_q_message.ip[0]

		# If we don't have this buddy in our list, add the buddy
		if have_buddy == False:
			print "Adding new buddy %s to the list" % new_buddy.name
			new_buddy.updateLastHeardTime()
			new_buddy.active = True
			self.list.append(new_buddy)
			return True
		else:
			# We already have this buddy
			# TODO: Update their last heard from time.
			buddy = self.getBuddyByName(new_buddy_name)
			buddy.updateLastHeardTime()

			# Since the buddy could have been in the list but been inactive,
			# and we have heard from them now, set them an active.
			# This should allow them to be added back to the BuddyList in the GUI.
			if buddy.isActive() == False:
				buddy.setActive()
				# Return true to indicate that we should update the GUI.
				return True

		return False

	def checkForBuddy(self, new_buddy_name):
		for index, buddy in enumerate(self.list):
			print index, buddy.name

			# We found this buddy in our list
			if buddy.name == new_buddy_name:
				return True

		# We didn't find the buddy in the list
		return False

	def getBuddy(self, index):
		return self.list[index]

	def getBuddyByName(self, name):
		for index, buddy in enumerate(self.list):
			# We found this buddy in our list
			if buddy.name == name:
				return buddy

		# We didnt' find the buddy in the list
		return None

	def cleanup(self):

		buddyListChanged = False
		# Scan through the list and look for buddies that we haven't heard from
		# in a while.  If we haven't heard from them, set to inactive.
		for index, buddy in enumerate(self.list):

			if buddy.getTimeSinceHeard() > self.buddyTimeout:
				#print "%s is now inactive" % buddy.name
				buddy.setInactive()
				buddyListChanged = True

		return buddyListChanged

class ChatServer:

	"""This class handles sending and receiving messages from indivdual buddies on the network.

	TODO: Add group chat messages.  This can be done over TCP first but it would be awesome to do multicast."""

	def __init__(self):

		print "ChatServer constructor"
		self.listen_stop = False

	def runServer(self, message_queue):

		print "runServer"
		tcpsocketHelper = TCPSocketHelper()
		self.tcpsock = tcpsocketHelper.createTCPSocket()

		# Listen for incoming connections
		self.tcpsock.listen(1)
		self.activeConnections = {}
		self.sendMessageToGUI = True

		while self.listen_stop == False:
			# Wait for a connection
			print >>sys.stderr, 'waiting for a connection'
			connection, client_address = self.tcpsock.accept()

			# TODO: Need a way of storing connections based on a connection seq no rather than client address
			# because we could have multiple connections from a client.  Although we could also prevent this on the client side.

			# TODO: When we receive a connection, we need to spawn a new thread here so we can talk to the client that just connected
			#       while also listening for new connections to come in.

			# It may be easier at first to just close the connection every time.  That way any time we recieve a message, we don't have to manage
			# multiple sockets, we just recieve the message, and pass the message to the GUI.  If we want to send a message to a client, we can
			# create a connection, send the message, then close it.  May be more overhead but will keep this program simplier for now.
			self.activeConnections[client_address[0]] = connection

			try:
				print >>sys.stderr, 'connection from', client_address
				print "Client %s:%d" % (client_address[0], client_address[1])

				# Receive the data in small chunks and retransmit it
				data = connection.recv(1024)
				print >>sys.stderr, 'received "%s"' % data

				if self.sendMessageToGUI:
					message = json.loads(data)

					if message:
						print "Got json message"
						print "Username = %s" % message['username']
						print "Message = %s" % message['message']

						q_message = QueueMessage()
						q_message.setMessageType(QueueMessage.INCOMING_MESSAGE)
						q_message.setClientIP(client_address[0])
						q_message.setUserName(message['username'])
						q_message.setMessage(message['message'])

						message_queue.put(q_message)
				
			finally:
				# Clean up the connection
				self.closeConnection(self.activeConnections[client_address[0]])

	def sendOutgoingMessage(self, buddy_address, buddy_port, message):
		# TODO: This function receives a message from the GUI and sends the message to the client specified if they are connected.

		# Create a TCP/IP socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# Connect the socket to the port where the server is listening
		destination_address = (buddy_address, buddy_port)
		print >>sys.stderr, 'connecting to %s port %s' % destination_address
		sock.connect(destination_address)

		try:
		    
		    # Send data
		    print >> sys.stderr, 'sending "%s"' % message
		    sock.sendall(message)

		    # Look for the response
		    amount_received = 0
		    amount_expected = len(message)
		    
		    #while amount_received < amount_expected:
		    #    data = sock.recv(64)
		    #    amount_received += len(data)
		    #    print >>sys.stderr, 'received "%s"' % data

		finally:
		    print >>sys.stderr, 'closing socket'
		    sock.close()

	def closeConnection(self, connection):
		print "closing connection"
		connection.close()

	def stopListen(self):
		self.listen_stop = True

class GuiPart:

	def __init__(self, master, message_queue, endCommand):

		self.master = master
		self.message_queue = message_queue
		self.stop = False
		self.endCommand = endCommand
		self.buddy_list = BuddyList()
		self.myUsername = "pfarrell"

		self.initialize()

	def initialize(self):

		self.master.geometry("950x500")
		bg_color = 'Grey'
		message_window_color = 'White'
		# create a menu
		menu = Menu(self.master)
		root.config(menu=menu)

		filemenu = Menu(menu)
		menu.add_cascade(label="File", menu=filemenu)
		filemenu.add_command(label="Set Username", command=self.setUsernameCallback)

		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=self.exitCallback)

		helpmenu = Menu(menu)
		menu.add_cascade(label="Help", menu=helpmenu)
		helpmenu.add_command(label="About...", command=self.helpCallback)

		# Buddy List Frame
		self.buddyListFrame = Frame(self.master, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.buddyListFrame.pack(side=LEFT, fill=BOTH, expand=1)

		# Buddy List Header Frame
		self.buddyListHeaderFrame = Frame(self.buddyListFrame, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.buddyListHeaderFrame.pack(side=TOP, fill=X)

		# Buddy List Header
		self.buddyListHeaderLabel = Label(self.buddyListHeaderFrame, text="Buddy List", bg=bg_color)
		self.buddyListHeaderLabel.pack()

		# Buddy List
		self.buddyListWindow = Listbox(self.buddyListFrame, borderwidth=2, relief=GROOVE)
		self.buddyListWindow.bind("<Double-Button-1>", self.OnDouble)
		self.buddyListWindow.pack(side=TOP, fill=BOTH)

		#self.buddyListWindow.insert(END, "test" + "\n")

		# Message Thread Frame (This is the frame that holds all the message sub-frames)
		self.messageThreadFrame = Frame(self.master, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.messageThreadFrame.pack(side=RIGHT, fill=BOTH, expand=1)

		# Message Header Frame
		self.messageHeaderFrame = Frame(self.messageThreadFrame, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.messageHeaderFrame.pack(side=TOP, fill=X)

		self.messageHeaderLabel = Label(self.messageHeaderFrame, text="Message Window", bg=bg_color)
		self.messageHeaderLabel.pack()

		# Message Display Frame
		self.messageDisplayFrame = Frame(self.messageThreadFrame, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.messageDisplayFrame.pack(side=TOP, fill=X)

		self.messageWindow = Text(self.messageDisplayFrame, borderwidth=2, relief=GROOVE, bg=message_window_color)
		self.messageWindow.pack(side=TOP, fill=X)

		# Message Input Frame
		self.messageInputFrame = Frame(self.messageDisplayFrame, borderwidth=2, relief=GROOVE, bg=bg_color)
		self.messageInputFrame.pack(side=BOTTOM, fill=X)

		self.message_input_content = StringVar()
		self.message_input = Entry(self.messageInputFrame, textvariable=self.message_input_content)
		self.message_input.pack(fill=X)

		self.send_button = Button(self.messageInputFrame, text="Send", width=6, command=self.sendCallback, bg=bg_color, fg="Blue")
		self.send_button.bind("<Return>", self.sendCallback)
		self.send_button.pack(side=LEFT, padx=2, pady=2)

		# Bind the return key so it sends the message when you press enter
		self.master.bind('<Return>', self.enterKeyCallback)

	def processIncoming(self):
		"""
		Handle all the messages currently in the queue (if any).
		This function gets called periodically to allow us to update the GUI asynchronously from events
		happening on the network.
		"""
		while self.message_queue.qsize():
			try:
				#print "got queue message"
				q_message = self.message_queue.get(0)

				if q_message.messageType == QueueMessage.DISCOVERY_MESSAGE: #TODO Add enum for buddy discovery message

					buddy_name = q_message.message

					# Check if we already know about this buddy.
					if self.buddy_list.processBuddyDiscoveryMessage(q_message):
						self.buddyListWindow.insert(END, buddy_name + "\n")
						self.buddyListWindow.pack()

				elif q_message.messageType == QueueMessage.INCOMING_MESSAGE:

					self.messageWindow.insert(INSERT, q_message.username + ": " + q_message.message + "\n")
					self.messageWindow.pack()

			except Queue.Empty:
				pass


	def exitCallback(self):
		if box.askquestion("Question", "Are you sure to quit?") == 'yes':
			print "Ending application"

	def enterKeyCallback(self, event):
		self.sendMessage()

	def getBuddyMessageWindow(self):

		NewWin = Toplevel(master=self.master)
		NewWin.title('New Window')
		NewWin.geometry('300x300')
		self.NewWinButton.config(state='disable')

		message_input = Entry(NewWin, width=50)
		message_input.pack()

		new_send_button = Button(NewWin, text="Send", width=6, command=self.sendCallback)
		new_send_button.bind("<Return>", self.sendCallback)
		new_send_button.pack(side=LEFT, padx=2, pady=2)

		def quit_win():
			NewWin.destroy()
			self.NewWinButton.config(state='normal')

		QuitButton = Button(NewWin,text='Quit',command=quit_win)
		QuitButton.pack()

		NewWin.protocol("WM_DELETE_WINDOW", quit_win)

	def cleanupBuddyList(self):

		buddyListChanged = self.buddy_list.cleanup()

		# TODO: Should we just clear the ListBox here and re-add all of the buddies, or
		# should we go through and delete each buddy that is in-active.
		# TODO: Ideally the Listbox item would be backed directly by the BuddyList structure
		#       but it looks like I would have to build this.

		# For now, if the buddy list changed. Delete all buddies and re-add only the active ones.
		if buddyListChanged == True:
			self.buddyListWindow.delete(0, END)

			for index, buddy in enumerate(self.buddy_list.list):
				# If the buddy is active, add them back ot the list
				if buddy.isActive():
					self.buddyListWindow.insert(END, buddy.name + "\n")
					self.buddyListWindow.pack()


	def OnDouble(self, event):
		widget = event.widget
		selection=widget.curselection()
		value = widget.get(selection[0])
		print "selection:", selection, ": '%s'" % value

	def sendCallback(self):
		self.sendMessage()

	def setUsernameCallback(self):
		pass

	def sendMessage(self):
		messageText = self.message_input.get()

		if len(messageText) > 0:
			# Clear the message input box
			self.message_input_content.set("")

			self.messageWindow.insert(INSERT, messageText + "\n")
			self.messageWindow.pack()

			message_box = {}
			message_box['username'] = self.myUsername
			message_box['message'] = messageText

			# The ListBox contains the name right now so look up buddy by name.
			# TODO: this is limiting because two people can't have the same name.  Change the list to
			# be backed by objects and be able to look up by user_names.
			buddyNameFromDisplayList = self.buddyListWindow.get(self.buddyListWindow.curselection())

			buddy = self.buddy_list.getBuddyByName(buddyNameFromDisplayList.strip())
			if buddy == None:
				print "Error: couldn't find buddy %s" % buddyNameFromDisplayList
				return

			# When we hit the send button, it needs to send a messaage back into the Chat server to create a socket
			# and send the message to the client.
			cs = ChatServer()
			cs.sendOutgoingMessage(buddy.ip, 10000, json.dumps(message_box))

	def helpCallback(self):
		box.showinfo("Information", "Chatter")

	def exitCallback(self):
		if box.askquestion("Question", "Are you sure to quit?") == 'yes':
			self.stop = True
			self.endCommand()

class ChatterApp:

	START_MULTICAST_DISCOVERY_SENDER_THREAD = True
	START_MULTICAST_DISCOVERY_LISTENER_THREAD = True
	START_TCP_LISTENER_THREAD = True

	def __init__(self, master, *args, **kwargs):
		"""
		Start the GUI and the asynchronous threads. We are in the main
		(original) thread of the application, which will later be used by
		the GUI. We spawn a new thread for the worker.
		"""

		# Create the queue to send messages to the GUI
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
			self.chatServer = ChatServer()
			self.chatServerThread = threading.Thread(target=self.tcpListenerThread)
			self.chatServerThread.start()

		# Start the periodic call in the GUI to check if the queue contains
		# anything
		self.running = 1
		self.periodicCall()

	def periodicCall(self):
		"""
		Check every 100 ms if there is something new in the queue.
		"""
		self.gui.processIncoming()

		# Run the Buddy List Cleanup to remove any buddies we haven't heard in a while.
		self.gui.cleanupBuddyList()

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
		self.chatServer.runServer(self.message_queue)

	def endApplication(self):
		if self.START_MULTICAST_DISCOVERY_SENDER_THREAD:
			self.mcastDiscoverySender.stopSending()

		if self.START_MULTICAST_DISCOVERY_LISTENER_THREAD:
			self.mcastDiscoveryListener.stopListen()

		if self.START_TCP_LISTENER_THREAD:
			self.chatServer.stopListen()

		self.running = 0
		sys.exit()

	def signal_handler(self, signal, frame):
	        print('You pressed Ctrl+C!')
	        self.endApplication()

if __name__ == '__main__':

	print "Starting Chatter"
	root = Tk()
	root.title("Chatter")

	app = ChatterApp(root)
	signal.signal(signal.SIGINT, app.signal_handler)
	root.mainloop()
