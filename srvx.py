#!/usr/bin/env python
"""
SrvX Module

Communicates with SrvX via QServer protocol
"""

__author__  = 'Gavin M. Roy <gavinmroy@gmail.com>'
__date__    = '2010-01-10'
__version__ = '0.1'

import logging
import random
import re
import socket
import time

# Create a common socket
connection = None

# Core Classes
class SrvX():

    def __init__(self, host='127.0.0.1', port=7702, password=None, auth_user=None, auth_password=None):

        global connection

        # Create our buffer string which will be used to hold info across responses if needed
        self.response = ''

        # By default we're not authenticated
        self.authenticated = False

        # If we don't have a connection, connect and authenticate
        if not connection:

            logging.info('Connecting to %s:%i' % (host, int(port)))

            # Create our socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect to our remote host
            connection.connect((host, int(port)))

            # Send the QServer username and password
            self._send_command('PASS %s' % password, True)

            # Authenticate
            self.authenticate(auth_user, auth_password)

        else:

            logging.debug('Re-using already authenticated and connected session')

    def authenticate(self, username, password):

        logging.debug('Processing AuthServ Authentication Request')

        # Send the AuthServ auth request
        response = self._send_command('AuthServ AUTH %s %s' % (username, password))

        # Parse the response
        if response['data'][0] == 'I recognize you.':
            logging.info('Authenticated with AuthServ')
            self.authenticated = True
        else:
            raise AuthServAuthenticationFailure(response['data'][0])

    def disconnect(self):

        logging.debug('Closing connection to QServer')
        connection.close()
        connection = None

    def generate_token(self):

        # Return a token generated from a random number
        return 'GS%05d' % random.randint(0,65535)

    def get_response(self):

        global connection

        data = ''
        command_length = 0
        response_done = False

        # Loop until the response is done
        while not response_done:

            # Append data from the socket into the global buffer
            self.response += connection.recv(32768)

            # Split the content into a list
            lines = self.response.split('\n')

            # Loop through each line in the list
            for line in lines:

                # If it finds the token
                if line.find(self.token) > -1:

                    logging.debug('Matched on token %s' % self.token)

                    # Do an initial split to so we know our response code
                    parts = line.split(' ')
                    response_code = parts[1]

                    # We did not auth with QServer Successfully
                    if response_code == 'X':
                        command_length += len(line)
                        logging.error('QServer Authentication Failure')
                        connection.close()
                        connection = None
                        raise QServerAuthenticationFailure()

                    elif response_code == 'S':
                        logging.debug('Got a S packet, processing more')
                        command_length += len(line) + 1
                        continue

                    elif response_code == 'E':

                        # We've reached the end of the response
                        logging.debug('Got a E packet, ending response')
                        command_length += len(line) + 1
                        response_done = True
                        break

                    else:
                        # Append the buffer
                        logging.debug('Unexpected line: "%s"' % line)
                        command_length += len(line) + 1
                        data += '%s\n' % line
                else:
                    command_length += len(line) + 1
                    data += '%s\n' % line


        # Remove our command from the response buffer
        self.response = self.response[command_length:]
        logging.debug('Processed %i bytes leaving %i bytes in the global buffer' % (command_length, len(self.response)))

        # Build our response packet
        response = {'data': []}
        lines = data.split('\n')
        for line in lines:

            if not response.has_key('from'):
                parts = line.split(' ')
                response['from'] = parts[0]

            content = line[line.find(':') + 1:]
            if len(content.strip()):
                response['data'].append(content.strip())

        # Return the response
        return response

    def _send_command(self, command, no_response = False):

        global connection

        # Get our token
        self.token = self.generate_token()

        # Put a token infront of the command
        command = '%s %s\n' % (self.token, command)

        # Send the command
        logging.debug('Sending: %s' % command.strip())
        connection.send(command)

        # return the response
        if not no_response:
            return self.get_response()

    def send_command(self, command):

        # If we're not authenticated do not send the command
        if not self.authenticated:
            raise SrvXNotAuthenticated

        # Send the command
        return self._send_command(command)

class AuthServ():

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise InvalidSrvXObject

    def _command(self, command):

        # Run the command in the srvx object
        return self.srvx._send_command('authserv %s' % command)

    def checkpass(self, account, password):

        # Check to see if the account and password are valid in returning bool
        response = self._command('checkpass %s %s' % (account, password))
        return response['data'][0] == 'Yes.'

class ChanServ():

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise InvalidSrvXObject

    def bans(self, channel):

        # List to hold our bans
        bans = []

        # Send our command to ChanServ
        response = self._command('bans %s' % channel)

        # Get the column positions
        c1 = 0
        c2 = response['data'][0].find('Set By')
        c3 = response['data'][0].find('Triggered')
        c4 = response['data'][0].find('Reason')

        # Loop through the response from the 2nd line
        for line in response['data'][2:len(response['data']) - 1]:

            # Append the dictionary for the row to the ban list
            bans.append({'mask': line[c1:c2].strip(),
                         'set_by': line[c2:c3 - 1].strip(),
                         'triggered': line[c3:c4 - 1].strip(),
                         'reason': line[c4:].strip()})

        # Remove the ban list dictionary
        return bans

    def _command(self, command):

        # Send the command through srvx
        return self.srvx.send_command('chanserv %s' % command)

    def clist(self, channel):

        # Use the generic users function
        return self.users(channel, 'clist')

    def info(self, channel):

        # Send our command to ChanServ
        response = self._command('info %s' % channel)

        # Build the initial dictionary
        info = {'channel': response['data'][0].split(' ')[0]}

        # Loop through the remaining lines and build a dictionary of values
        for line in response['data'][1:]:
            parts = line.split(':')
            if len(parts) > 1:
                info[parts[0].strip()] = parts[1].strip()
            else:
                if len(line.strip()) > 0:
                    logging.error('Odd info response: %s' % line)

        # Return the dictionary
        return info

    def mlist(self, channel):

        # Use the generic users function
        return self.users(channel, 'mlist')

    def say(self, channel, message):

        # Send the say command, we don't care about the response
        self._command('say %s %s' % (channel, message))

    def olist(self, channel):

        # Use the generic users function
        return self.users(channel, 'olist')

    def plist(self, channel):

        # Use the generic users function
        return self.users(channel, 'plist')

    def users(self, channel, list_type = 'users'):

        # List to put users in
        users = []

        # Get the userlist data
        response = self._command('%s %s' % (list_type, channel))

        # Get the column positions
        c1 = 0
        c2 = response['data'][1].find('Account')
        c3 = response['data'][1].find('Last Seen')
        c4 = response['data'][1].find('Status')

        # Loop through the response from the 2nd line
        for line in response['data'][2:len(response['data'])]:

            if line[0:4] != 'None':
                users.append({'access': line[c1:c2].strip(),
                              'account': line[c2:c3 - 1].strip(),
                              'last_seen': line[c3:c4 - 1].strip(),
                              'status': line[c4:].strip()})

        return users

    def wlist(self, channel):

        # Use the generic users function
        return self.users(channel, 'wlist')


class OpServ():

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise InvalidSrvXObject

    def _command(self, command):

        # Run the command in the srvx object
        return self.srvx.send_command('opserv %s' % command)


# Exceptions
class AuthServAuthenticationFailure(Exception):
    pass

class QServerAuthenticationFailure(Exception):
    pass

class InvalidSrvXObject(Exception):
    pass

class SrvXNotAuthenticated(Exception):
    pass

# If run via the command line
if __name__ == '__main__':
    import optparse

    usage = "usage: %prog [options] [class function args]"
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
    logging.basicConfig(level=logging.INFO)

    if len(args) >= 2:

        # Intialize srvx
        srvx = SrvX(options.ipaddr, options.port, options.password, auth[0], auth[1])

        class_name = args[0].lower()
        function_name = args[1]

        if class_name == 'authserv':
            obj = AuthServ(srvx)
        elif class_name == 'chanserv':
            obj = ChanServ(srvx)
        elif class_name == 'opserv':
            obj = OpServ(srvx)

        # Get the function handle
        function = getattr(obj, function_name)

        logging.debug('Calling %s.%s' % (class_name, function_name))

        # Call the object function
        if len(args) == 3:
            print function(args[2])
        elif len(args) == 4:
            print function(args[2], args[3])
        elif len(args) == 5:
            print function(args[2], args[3], args[4])
        elif len(args) == 6:
            print function(args[2], args[3], args[4], args[5])