from .protocol import *

def Communicator(*a,**kw):
	global Communicator
	from .communicators.communicator import Communicator
	return Communicator(*a,**kw)

def SerialCommunicator(*a,**kw):
	global SerialCommunicator
	from .communicators.serialcommunicator import SerialCommunicator
	return SerialCommunicator(*a,**kw)

def TCPCommunicator(*a,**kw):
	global TCPCommunicator
	from .communicators.tcpcommunicator import TCPCommunicator
	return TCPCommunicator(*a,**kw)

