
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

import os
import sys
from Tkinter import *
import time
import Tkconstants, tkFileDialog


class GuiPart:

	def __init__(self, master):

		self.master = master

		self.initialize()

	def initialize(self):

		self.master.geometry("450x500")
		# create a menu
		menu = Menu(self.master)
		root.config(menu=menu)

		filemenu = Menu(menu)

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

class ChatterApp:

	def __init__(self, master, *args, **kwargs):
		"""
		Start the GUI and the asynchronous threads. We are in the main
		(original) thread of the application, which will later be used by
		the GUI. We spawn a new thread for the worker.
		"""
		self.master = master

		# Set up the GUI part
		self.gui = GuiPart(master)


if __name__ == '__main__':

	print "Starting Chatter"
	root = Tk()
	root.title("Chatter")

	app = ChatterApp(root)
	root.mainloop()
