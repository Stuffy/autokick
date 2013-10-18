# Importing sqlite libs to read the TeamSpeak database.
from sqlite3 import dbapi2 as sqlite
import string
import sys, time, os
import re
import Queue
import socket
from datetime import datetime
import binascii
import struct
from thread import start_new_thread, allocate_lock

# ------------------- Settings ------------------- #

# Ip of the TeamSpeak-server, should be 127.0.0.1 most of the time.
ts_query_ip = '127.0.0.1'
# TeamSpeak query port, should be 10011 most of the time
ts_query_port = 10011
# User to connect as
ts_query_user = 'serveradmin'
# Password of that user
ts_query_password = ''
# VServer-ID, if you have more than one server running, change this to the number you'd like the bot to check
ts_query_vsid = '1'

# Ip of the BattleEye server. It's the same one the arma2 server uses
be_server_ip = ''
# BE server port. Can vary. Check your server.cfg
be_server_port = 2402
# BE admin password. Needed for the bot to connect.
be_server_password = ''

# ----------------------------------------------- #

users = []

# RegEx for filtering out ip+port
p = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:[0-9]{1,5}')

# Create a lock for threading
lock = allocate_lock()
lock_ts = allocate_lock()

# Queue object to pass object into threads or receive objects from threads
fooResult = Queue.Queue()

# Variable to keep track of the battle-eye command sequence
sequence = 0

# method the create a socket, either udp or tcp, should be self explaining
def create_socket(protocol):
	try:
		if protocol == 'TCP':
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		elif protocol == 'UDP':
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		return s
	except socket.error, msg:
		print '[' + str(datetime.now()) + '] ' + 'Failed to create socket. Error code: ' + str(msg[0]) + ' , Error message : ' + msg[1]
		sys.exit()

# Method to connect a socket to a specific adress and port
def connect(host, port, s):
	try:
		remote_ip = socket.gethostbyname(host)
	except socket.gaierror:
		print '[' + str(datetime.now()) + '] ' + 'Hostname could not be resolved. Exiting'

	try:
		s.connect((remote_ip, port))
	except socket.error:
		print '[' + str(datetime.now()) + '] ' + 'Connecting failed on ' + host
		sys.exit()

# Send a message to a port. This is used to send the packets structured with the becon-method below aswell as
# sending the ts3-querys which need no packing at all
def sendmessage(s, message):
	try:
		s.sendall(message)
	except socket.error:
		print '[' + str(datetime.now()) + '] ' + 'Socket send failed (Ts3query)'
		sys.exit()

# Receive messages from a socket. This is used only for teamspeak since bercon messages need special handling
def receivemessage(s):
	while 1:
		lock_ts.acquire()
		reply = s.recv(4096)
		lock_ts.release()
		reply_lines = reply.split('\n')
		for line in reply_lines:
			# Probably unsafe since it just checks if the string clid= is in the current line
			if 'clid=' in line:
				fooResult.put(line)	

# Handle replys from the bercon socket. Note that this takes the already stripped message from becon_receivemessage,
# so theres no header in it anymore, only the payload of the packet
def handle_reply(reply):
	# Sub-Array for the global array users
	# db_id, arma_id, join_time(posix), ip, in_teamspeak, times_warned
	dtary = [0, 0, 0, 0, 0, 0]
	
	global users

	reply_lines = reply.split('\n')
	# Below some checking if the reply is a "player connected" string
	if len(reply_lines) == 1:
		reply_words = reply_lines[0].split(' ')
		if len(reply_words) == 5:
			if reply_words[0] == 'Player' and reply_words[4] == 'connected':
				# After we are sure its the correct reply, get the ip and arma_id (Player id) from the string
				ipstring = reply_words[3].replace('(', '')
				ipstring = ipstring.replace(')', '')
				ipstring = ipstring.split(':')
				ipstring = ipstring[0]
				arma_id = reply_words[1].replace('#','')
				
				# inteamspeak var
				its = -1
				# Do the intial check if the user is in teamspeak
				if (check_teamspeak(ipstring) == False):
					# if false, start with already 1 warning given and set the its var to 0 (means not in teamspeak)
					its = 0
					warnings = 1
					print '[' + str(datetime.now()) + '] ' + 'User ' + reply_words[1] + ' is NOT connected to TS'
				elif (check_teamspeak(ipstring) == True):
					# if true, set its to 1 (means he is in teamspeak)
					its = 1
					warnings = 0
					print '[' + str(datetime.now()) + '] ' + 'User ' + reply_words[1] + ' is connected to TS'
				elif (check_teamspeak(ipstring) == 'ERROR'):
					# if the method returns ERROR, something went wrong while checking
					print '[' + str(datetime.now()) + '] ' + 'Error while checking TS'

				# Fill vars into array and append to the global user array
				dtary = [-1, arma_id, time.time(), ipstring, its, warnings]
				users.append(dtary)
			# Remove array entry if user disconnects from the server
			elif reply_words[0] == 'Player' and reply_words[3] == 'disconnected':
				arma_id = reply_words[1].replace('#','')
				for i in range(0, len(users)):
					if users[i][1] == str(arma_id):
						users.pop(i)
						print '[' + str(datetime.now()) + '] ' + 'User' + reply_words[1] + 'removed from array (Disconnect)'

# Check if the user connected to teamspeak via the database and query
def check_teamspeak(ip):
	global users

	# Create a connection and a cursor to parse the sqlite database
	# NOTE: I have to do this every time since this gets called in a thread and cursor objects cant be used from threads
	# other than threads that created it
	connection = sqlite.connect('ts3server.sqlitedb')
	cursor = connection.cursor()

	rowcount = 0
	# might be ineffective
	# Select based on the ip
	cursor.execute('SELECT * FROM clients WHERE client_lastip="' + ip + '" order by client_lastconnected desc')


	for row in cursor:
		# send the command to print the connected clients to the tsquery-socket
		sendmessage(s, 'clientlist\n')

		# Loop as long as the query-object is empty
		while True:
			if (fooResult.empty() == False):
				result = fooResult.get()
				# split the result, | is the delimiter of tsquery between two differend users
				result = result.split('|')
				# Filter out the client_database_id, since thats the bit thats interessting for us
				for client in result:
					prm = client.split(' ')
					for subprm in prm:
						val = subprm.split('=')
						if (val[0] == 'client_database_id'):
							# Check if the database_id from the query matches with the database_id from the database
							# if yes, the users is connected to teamspeak and we can return true and exit the loop
							if (val[1] == str(row[0])):
								connection.close()
								return True
								break
				# If we reach this, no match between the database_ids was found, meaning we can exit with false (user not connected to teamspeak)
				connection.close()
				return False				
				break
		# Add up the rowcount
		rowcount += 1

	# if the rowcount is 0, no rows where returned, meaning that the user never connected to the teamspeak server,
	# so he cant be connected to teamspeak, thus return false
	if rowcount == 0:
		connection.close()
		return False

	# if we reach this something went wrong
	connection.close()
	return 'ERROR'

# Thread method to check the teamspeak
def check_timed_ts():
	global users
	print '[' + str(datetime.now()) + '] ' + 'TeamSpeak check-thread started'
	while True:
		if (len(users) >= 0):
			for i in range(0, len(users)):
				if (check_teamspeak(users[i][3]) == False):
					if (users[i][5] % 3 == 0):
						sendmessage(b, becon_cmdpacket(False, 'say ' + str(users[i][1]) + ' You are not logged into TeamSpeak! Warning ' + str(users[i][5] / 3) + '/4. Join it!'))
						users[i][5] += 1
						print '[' + str(datetime.now()) + '] ' + 'Warning given to user '
					else:
						print '[' + str(datetime.now()) + '] ' + 'User not in teamspeak. Warnings: ' + str(users[i][5])
						users[i][5] += 1
					if (users[i][5] % 12 == 0):
						print '[' + str(datetime.now()) + '] ' + 'User kicked off (Not it teamspeak)'
						sendmessage(b, becon_cmdpacket(False, 'kick ' + str(users[i][1])))
						users.pop(i)
				elif (check_teamspeak(users[i][3]) == True):
					print '[' + str(datetime.now()) + '] ' + 'User is in teamspeak.'
		time.sleep(10)

# 
# NOTE: This is only a rough explanation of what I did, for more infos please refer to
# http://www.battleye.com/downloads/BERConProtocol.txt
#

# Method to filter out the payload from the battle-eye return packets
def becon_receivemessage(s):
	start_new_thread(becon_keepalive,(s,))
	while 1:
		# Aquire lock so the other threads wait for us
		lock.acquire()
		reply = s.recv(4096)
		lock.release()
		# Checking the first byte to determine the kind of message
		# 2 means its a server message ( no response to a command send from us ! ), so send back a acknowledge-packet so the server knows we've got the packet
		if ord(reply[7:8]) == 2:
			sendmessage(s, becon_acknowledge(ord(reply[8:9])))
			print reply[9:]
			# Pass it to the reply handeling function.
			handle_reply(reply[9:])
		# If its a 1, its means its a response from the server, so we do the same as above
		elif ord(reply[7:8]) == 1:
			if reply[9:] != '':
				# NOTE: Need clearification if a response packet needs to be acknoledged
				sendmessage(s, becon_acknowledge(ord(reply[8:9])))
				print reply[9:]
				handle_reply(reply[9:])
		# If its 0 ( not null ! ), its either a login response or a multi packet-packet ( eh.. )
		elif ord(reply[7:8]) == 0:
			# So we check the second byte to determine what it is
			# If its 0, its a rejected login packet, so say that to the user...	
			if ord(reply[8:9]) == 0:
				print '[' + str(datetime.now()) + '] ' + 'Login packet rejected'
			# If its bigger than 0, its a accepted login packet OR multiple packets.
			# Since we didn't get a login reject, and multiple packets are rarly used, we just pass and continue
			elif ord(reply[8:9]) > 0:
				pass
				# todo: multipacket handeling here

# Packet send to the BE-server with the login informations
# Since the beserver wants a crc32 checksum of the payload, we are going to do that for him
def becon_loginpacket(password):
	# Construct the message body
	# Since its a login packet, put a 0-byte in front of the password
	message = '\x00' + password
	# After that, add the normal FF-byte in front of the message, like we do it with all packets
	message = '\xFF' + message
	# Create the checksum
	checksum = binascii.crc32(message) & 0xffffffff
	# Pack checksum as signed 4 byte int
	checksum = struct.pack('l', checksum)
	# Only use the first 4 byte of the checksum ( sometimes its longer )
	checksum = checksum[:4]
	return 'BE' + checksum + message

# Method to send a command-packet OR a keepalive packet
def becon_cmdpacket(keepalive, cmd):
	# Define the global var sequence to keep track of the messages send
	global sequence

	# Check if its a keepalive packet
	if keepalive == False:
		# If its a normal command packet, send everything
		message = '\x01' + unichr(sequence) + cmd
		sequence += 1
	else:
		# If its a keepalive packet, we only need to send the sequence but not increase it
		# NOTE: Not sure if this is the correct way, but it works
		message = '\x01' + unichr(sequence)
		print '[' + str(datetime.now()) + '] ' + "Keepalive packet send"
	# Convert the message to a bytearray for sending
	message = '\xFF' + bytearray(message, 'utf-8')
	# See becon_loginpacket
	checksum = binascii.crc32(message) & 0xffffffff
	checksum = struct.pack('l', checksum)
	checksum = checksum[:4]
	return 'BE' + checksum + message

# Method to send a packet acknowledge to the server
# Same as the above functions
def becon_acknowledge(sequence):
	message = '\x02' + unichr(sequence)
	message = '\xFF' + bytearray(message, 'utf-8')
	checksum = binascii.crc32(message)
	checksum = struct.pack('l', checksum)
	checksum = checksum[:4]
	return 'BE' + checksum + message

# Thread function to send the keepalive packets at 30 second intervals
def becon_keepalive(s):
	timer = 0
	while True:
		if timer < 30:
			time.sleep(1)
			timer += 1
		else:
			# fooBar is not send, it's just a placeholder since its a keepalive packet
			sendmessage(s, becon_cmdpacket(True, 'fooBar'))
			timer = 0

s = create_socket('TCP')
b = create_socket('UDP')

# Connect the ts3query server socket
connect(ts_query_ip, ts_query_port, s)
# Connect the bercon server socket
connect(be_server_ip, be_server_port, b)

# Start the thread to receive messages from the ts3query socket
start_new_thread(receivemessage,(s,))
# Start the thread to check the player on the arma2 server
start_new_thread(check_timed_ts, ())

# Start the thread to receive bercon messages
start_new_thread(becon_receivemessage,(b,))

sendmessage(b, becon_loginpacket(be_server_password))

sendmessage(s, 'login client_login_name=' + ts_query_user + ' client_login_password=' + ts_query_password + '\n')
sendmessage(s, 'use ' + ts_query_vsid + '\n')

while True:
	c = raw_input()
	sendmessage(b, becon_cmdpacket(False, c))