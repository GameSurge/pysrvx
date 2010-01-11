#!/usr/bin/env python
"""
SrvX Module

Communicates with SrvX via QServer protocol
"""

__author__  = 'Gavin M. Roy <gavinmroy@gmail.com>'
__date__    = '2010-01-10'
__version__ = '0.1'

import asyncore
import logging
import random
import socket
import time

# Core Classes
class SrvX(asyncore.dispatcher):

    def __init__(self, host='127.0.0.1', port=7702, password=None, auth_user=None, auth_password=None):

        logging.info('Connecting to %s:%i' % (host, int(port)))
        
        # Initialize the class we extended
        asyncore.dispatcher.__init__(self)
        
        # Create our socket
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to our remote host
        self.connect((host, int(port)))
        
        # By default we're not authenticated
        self.authenticated = False

        # Create our command dictionary, holds state of commands
        self.commands = []
        self.sent_commands = []
        
        # Reading State, we receive responses synchronically so process one response until it ends
        self.processing_packet = False
        self.response_buffer = ''
         
        # Send the QServer username and password 
        self.send_command('PASS %s' % password)
        
        # Send the AuthServ auth request
        self.send_command('AuthServ AUTH %s %s' % (auth_user, auth_password), self.auth_response)

    def auth_response(self, response):
        # Callback function for when we try and authenticate with Authserv        
        logging.debug('Processing AuthServ Authentication Request')
        
        # Set message format, if it matches, we authed otherise raise an exception
        if response[0]['message'] == 'I recognize you.':
            logging.info('Authenticated with AuthServ')
            self.authenticated = True
        else:
            raise AuthServAuthenticationFailure(response[0]['message'])

    def handle_connect(self):
        pass

    def handle_close(self):
        logging.debug('Closing connection to QServer')
        self.close()

    def handle_read(self):
        response = self.recv(8192)
        logging.debug('Received: %s' % response.strip())
        
        lines = response.split('\n')
        
        for line in lines:
        
            logging.debug('New Line: %s' % line)
            if not self.processing_packet:
                
                # Loop through our dictionary of commands to find which command we're responding to
                for command in self.sent_commands:
                                        
                    # If it finds the token
                    if line.find(command['token']) > -1:
                    
                        logging.debug('Matched on token %s' % command['token'])
                        
                        # Do an initial split to so we know our response code
                        parts = line.split(' ')
                        response_code = parts[1]
                        logging.debug('Response code: %s' % response_code)
                        
                        # We did not auth with QServer Successfully
                        if response_code == 'X':
                            self.shutdown()
                            raise QServerAuthenticationFailure()
                        
                        elif response_code == 'S':
                            logging.debug('Got a S packet, processing more')
                            self.processing_packet = True
                            self.response_buffer = ''
                            continue

                        else: 
                            'Unexpected response: %s' % line

            else:

                # Loop through our dictionary of commands to find which command we're responding to
                for command in self.sent_commands:
                                        
                    # If it finds the token
                    if line.find(command['token']) > -1:
                    
                        logging.debug('Matched on token %s' % command['token'])
                        
                        # Do an initial split to so we know our response code
                        parts = line.split(' ')
                        response_code = parts[1]
                        logging.debug('Response code: %s' % response_code)
     
                        if response_code == 'E':
                            self.processing_packet = False
                            self.process_buffer(command['token'])
                            continue
                        else: 
                            # Append the buffer
                            logging.debug('Unexpected line: "%s"' % line)
                            self.response_buffer += '%s\n' % line
                            continue

                # Append the buffer
                logging.debug(' Appending buffer with "%s"' % line)
                self.response_buffer += '%s\n' % line
                continue

    def handle_write(self):
    
        # While we have commands to send
        while len(self.commands):
        
            # Get the command off the list
            command = self.commands.pop(0)
            
            logging.debug('Sending: %s' % command['command'].strip())
            self.send(command['command'])

            # Set the sent time and append to our sent_commands stack
            command['sent_at'] = time.time()
            self.sent_commands.append(command)

    def process_buffer(self, token):

        # Pull out of the shared buffer
        response = self.response_buffer
        logging.debug('Processing buffer for token %s' % token)
        
        # Pull the sent command off the stack to process
        offset = 0
        for command in self.sent_commands:
            if command['token'] == token:
                break
            offset += 1

        # Remove it from the stack
        self.sent_commands.pop(offset)

        # Split our response into individual lines
        lines = response.split('\n')     
        
        # Create a new list for the response
        response = []
        
        # Loop through the lines
        for line in lines:
        
            # Find the first :
            delimiter_position = line.find(':')
            
            # Get the base packet info
            packet_info = line[0:delimiter_position].split(' ')
            if len(packet_info) > 2:
                response.append({'from': packet_info[0],
                                 'response_type': packet_info[1],
                                 'message': line[delimiter_position + 1:].replace(chr(0x02), '"')})
        
        # If we have a callback command, run it
        if command['callback']:
            command['callback'](response)

    def send_command(self, command, callback = None):
    
        # Get our token
        token = self.token()
        
        # Put a token infront of the command
        command = '%s %s\n' % (token, command)

        # Add to our command stack
        self.commands.append({'token': token,
                              'command': command, 
                              'callback': callback, 
                              'sent': False,
                              'timestamp': time.time()})
    
    def shutdown(self):
    
        # Close the socket
        self.close()
    

    def token(self):
        
        # Return a token generated from a random number        
        return 'GS%05d' % random.randint(0,65535)

    def writable(self):
        
        # If we have any commands let asyncore know we can send
        if len(self.commands) > 0:
            return True
        return False
        
class AuthServ:

    def __init__(self):
        pass        

class ChanServ:

    def __init__(self):
        pass        

class OpServ:

    def __init__(self):
        pass
        
# Exceptions
class AuthServAuthenticationFailure(Exception):
    pass
    
class QServerAuthenticationFailure(Exception):
    pass
    
# If run via the command line
if __name__ == '__main__':

    import optparse
    
    usage = "usage: %prog [options]"
    version_string = "%%prog %s" % __version__
    description = "Command Line SrvX Tool"
    
    # Create our parser and setup our command line options
    parser = optparse.OptionParser(usage=usage,
                                   version=version_string,
                                   description=description)
 
    parser.add_option("-i", "--ipaddr", action="store", dest="ipaddr", 
                        default='127.0.0.1',
                        help="Host IP Address")     

    parser.add_option("-p", "--port", action="store", dest="port", 
                        default=7702,
                        help="Host TCP Port")     

    parser.add_option("-k", "--password", action="store", dest="password", 
                        help="QServer password")     

    parser.add_option("-a", "--auth", action="store", dest="auth", 
                        help="AuthServ username:password pair to use")     
                         
    # Parse our options and arguments                                                                        
    options, args = parser.parse_args()    

    # Make sure they passed in the password and auth string
    if not options.password or not options.auth:
        print 'Error: missing required parameters'
        parser.print_help();

    # Make sure the auth string is in foo:bar format
    auth = options.auth.split(':')
    if len(auth) < 2:
        print 'Error: invalid authserv credentials'
        parser.print_help();
    
    # Turn on debug logging
    logging.basicConfig(level=logging.DEBUG)
    
    srvx = SrvX(options.ipaddr, options.port, options.password, auth[0], auth[1])

    asyncore.loop()