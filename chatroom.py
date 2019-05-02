##
# Roland Oruche - Lab 3
##

import sys
import argparse
import json
import re
import socket
import threading

##
# Creating a class client connection that will:
# sign up the user, log them in, and/or validate the user
##
class ClientConnection(threading.Thread):
	def __init__(self, parent, socket, address):
		threading.Thread.__init__(self)
		self.parent = parent
		self.socket = socket
		self.address = address
		self.userid = ""
    
    ##
    # run - The server will run and load up a signup/login
    # for the user
    # @params - self
    ##
	def run(self):
		print("[server] New client connection from {0}.".format(self.address))
        
		self.send("My chat room client. Version Two >")
		
		self.loggedIn = False
		pattern = re.compile("(?P<command>login|newuser) (?P<username>\w*) (?P<password>\w*)")
		while not self.loggedIn:
			loginResponse = self.receive()
			match = pattern.match(loginResponse)
			if not match: # Invalid if the credentials do not match
				self.send("Invalid. Please try again.")
				continue
			else:
				command = match.group('command')
				userid = match.group('username')
				password = match.group('password')
			uidList = []
			for user in self.parent.users:
				uidList.append(user['userid'])

			if command == "login":
				if self.parent.isRegistered(userid): # Check if the user is already logged in
					self.send("You are already logged in.")
					continue
				if userid in uidList:
					for user in self.parent.users:
						if userid == user['userid'] and password == user['password'] and not self.parent.isRegistered(userid):
							self.send("Success! Hello, {0}!".format(user['userid']))
							self.userid = user['userid']
							self.loggedIn = True
					if not self.loggedIn: self.send("Invalid password. Please try again.")						
				else:
					self.send("Username not found. Please try again")
			elif command == "newuser":
				if match.group('username') in uidList: # If the user name already exists
					self.send("The username already exists. Please try again.")
				elif len(match.group('username')) > 32: # If the user name is greater than 32
					self.send("Invlaid. Please choose a username short that 32 chars.")
				elif len(match.group('password')) not in range(4,8): # If the password is not in the range between 4 and 8
					self.send("Invalid. Passwords must be between 4 and 8 characters long.")
				else: # Otherwise accept the user as they successfull signed up
					self.userid = match.group('username')
					self.parent.addUser(match.group('username'), match.group('password'))
					self.send("Successful! Hello, {0}!".format(self.userid))
					self.loggedIn = True
					continue

		print("[server] {0} login confirmed.".format(self.userid))
		self.parent.register(self.userid, self)

		pattern = re.compile("(?P<command>send|who|logout) ?(?P<args>.*)?")
		sendPattern = re.compile("(?P<recepient>\w*) (?P<message>.*)")
		while True:
			msg = self.receive()
			match = pattern.match(msg)
			if not match:
				self.send("Unknown command. Please try again.")
				continue
			if match.group('command') == "who": # Check to see other clients in the chatroom
				uidList = []
				for conn in self.parent.activeConnections:
					uidList.append(conn[0])
				self.send("{0} in the chatroom right now: {1}".format(len(uidList), ", ".join(uidList)))
			elif match.group('command') == "send": # Send to either all clients or one
				sendMatch = sendPattern.match(match.group('args'))
				if not sendMatch:
					self.send("Invalid. Please try again.")
					continue
				elif sendMatch.group('recepient') == "all":
					self.parent.sendToAll(self.userid, sendMatch.group('message'))
				else:
					sent = False
					for conn in self.parent.activeConnections:
						if conn[0] == sendMatch.group('recepient'):
							self.parent.sendToUser(self.userid, sendMatch.group('recepient'), sendMatch.group('message'))
							sent = True
					if not sent: self.send("{0} isn't in the chatroom at the moment.".format(sendMatch.group('recepient')))
			elif match.group('command') == "logout": # User wants to logout
				self.send("Goodbye.")
				break
		print("[server] {0} logout confirmed.".format(self.address))
		self.exit()
    
    ##
    # send - sending the message
    # @params - self, msg
    ##
	def send(self, msg):
		msg += ('\n')
		self.socket.send('{payload: <{maxlen}}'.format(payload=msg, maxlen=1024).encode('utf-8'))
    
    ##
    # receive - receiving the image
    # @params - self
    ##
	def receive(self):
		msg = b""
		while len(msg) < 1024:
			msg += self.socket.recv(1024 - len(msg))
		return msg.decode('utf-8').split('\n', 1)[0]
    ##
    # exit - exit soclet
    # @params - self
    ##
	def exit(self):
		self.socket.close()
		self.parent.unregister(self.userid)

##
# Creating a Server class that connects the config file
# and sets up the socket
##
class Server():
	def __init__(self, configPath):
		self.error = False
		self.run = True
		self.activeConnections = []
		print("[server] Loading server configuration..")
		self.configPath = configPath[0]
		self.loadConfig(configPath[0])
		if not self.error:
			print("[server] Loading up server socketAPI..")
			self.setupSocket()

    ##
    # loadConfig - attempts to open the passed config file path
    # @params - self, configPath
    ##
	def loadConfig(self, configPath):
		try:
			with open(configPath) as f: # Opens up the json file and verifies if it is one
				try:
					jsonConfig = json.load(f)
				except:
					print("[Error] (server) Configuration file passed is not valid json.")
					self.error = True
				try:
					self.host = jsonConfig['host']
					self.port = jsonConfig['port']
					self.maxClients = jsonConfig['maxclients']
					self.users = jsonConfig['users']
				except KeyError:
					print("[Error] (server) Could not parse required parameters from config file at '{0}'".format(configPath))
					self.error = True
		except FileNotFoundError:
			print("[Error] (server) Could not open configuration file at '{0}' for reading.".format(configPath))
			self.error = True

    ##
    # saveConfig - Saves off relevant server states into json format
    # to the same file path that was passed to it at creation.
    # @params - self
    ##
	def saveConfig(self):
		config = {
            "host" : self.host, # localhost
            "port" : self.port, # 16843
            "maxclients" : self.maxClients, # 3
            "users" : self.users # users
		}
		with open(self.configPath, 'w') as of:
			json.dump(config, of)
    
    ##
    # setupSocket - creates socket object and sets it up
    # @params - self
    ##
	def setupSocket(self):
		try:
			self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.server.bind((self.host, self.port))
		except:
			print("[Error - server] Failed to open server socket.")
			self.error = True

    ##
    # start - starts the server for the chatroom
    # if it is full, the socket closes
    # @params - self
    ##
	def start(self):
		print("[server] Incoming connections from {0}:{1}...".format(self.host, self.port))
		while self.run:
			self.server.listen(1)
			clientSocket, clientAddress = self.server.accept()
			if len(self.activeConnections) == self.maxClients: # If the maxClients is exceeded, close the client socket
				clientSocket.send("Chatroom is full, try again later.".encode('utf-8'))
				clientSocket.close()
				print("[server] The number of connections {0} is exceeding...".format(self.maxClients))
				continue
			clientThread = ClientConnection(self, clientSocket, clientAddress)
			clientThread.start()
		print("[server] Closing socket.")
		self.server.close()
    
    ##
    # register - adds the client thread supplied in objRef to the pool of active connections
    # @params - self, id, objRef
    ##
	def register(self, id, objRef):
		for user in self.activeConnections:
			user[1].send("{0} has joined the chatroom.".format(id))
		self.activeConnections.append((id, objRef))
    
    ##
    # unregister - removes the supplied id from the list of active connections
    # @params - self, uid
    ##
	def unregister(self, id):
		for i, ct in enumerate(self.activeConnections):
			if id == ct[0]:
				del self.activeConnections[i]
		for user in self.activeConnections:
			user[1].send("{0} has left the chatroom.".format(id))

    ##
    # isRegistered - returns True if the provided userid is current registered
    # (logged in) to the server, False otherwise
    # @params - self, uid
    ##
	def isRegistered(self, uid):
		
		for user in self.activeConnections:
			if user[0] == uid:
				return True
		return False
    ##
    # addUser - appends new user in the saved config file
    # @params - self, uid, pass
    ##
	def addUser(self, uid, password):
		self.users.append({'userid': uid, 'password': password})
		self.saveConfig()
    
    ##
    # sendToAll - sends to all users in the chatroom
    # @params - self, senderID, message
    ##
	def sendToAll(self, senderID, message):
		for conn in self.activeConnections:
			conn[1].send("{0}: {1}".format(senderID, message))
		print("[server] {0} (to all): {1}".format(senderID, message))
    
    ##
    # sendToUser - sends to another user in the chatroom
    # @params - self, senderID, uid, message
    ##
	def sendToUser(self, senderId, uid, message):
		for conn in self.activeConnections:
			if conn[0] == uid:
				conn[1].send("{0} says to you: {1}".format(senderId, message))
		print("[server] {0} (to {1}): {2}".format(senderId, uid, message))

    ##
    # exit - Quit the application
    # @params - self
    ##
	def exit(self):
		self.run = False
		return

##
# Creating a Client class that checks to see if its connected
# to the socketAPI
##
class Client():
	def __init__(self, server, port):
		self.run = False
		self.server = server
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
	def connect(self):
		try:
			self.socket.connect((self.server, self.port))
			return True
		except:
			print("[Error - client] Server is not running.")
		return False
            
	def listen(self):
		while self.run:
			recvData = self.socket.recv(1024)
			if recvData:
				print(">> {0}".format(recvData.decode().split('\n', 1)[0]))
			else:
				self.stop()

	def send(self, msg):
		msg += '\n'
		try:
			self.socket.sendall('{payload: <{maxlen}}'.format(payload=msg, maxlen=1024).encode('utf-8'))
		except:
			print("[Error - client] Connection to server lost.")
			return False
		return True

	def start(self):
		self.run = True
		listenThread = threading.Thread(target=self.listen)
		listenThread.start()

	def stop(self):
		self.run = False
		self.socket.close()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="A Basic Chatroom Application.", epilog="By default, will run in client mode.")
	parser.add_argument("-s", "--server", help="Runs the application in server mode.", action="store_true")
	parser.add_argument("-c", "--config", nargs=1, help="Specifies path to the json config information for the application.", action="store")
	args = parser.parse_args()

	if args.server:
		if not args.config:
			print("[Error - server] No config specified --config, -c.")
			sys.exit(1)
		server = Server(args.config)
		if server.error:
			print("[Error - server] Server could not be initialized. Exiting.")
			sys.exit(1)
		server.start()
	else:
		SERVER = "localhost"
		PORT = 16843
		client = Client(SERVER, PORT)
		if client.connect():
			client.start()
			while True:
				output = input("")
				if output == "logout":
					client.send("logout")
					client.stop()
					break
				else:
					if not client.send(output):
						break
		sys.exit()
