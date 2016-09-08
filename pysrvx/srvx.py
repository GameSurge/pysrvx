"""
srvx is the main QServer communication routines

"""
from __future__ import unicode_literals

from logging import getLogger
from random import randint
from socket import socket, error as socket_error, AF_INET, SOCK_STREAM


# Exceptions
class SrvXError(Exception):
    pass


class AuthenticationError(SrvXError):
    pass


class ConnectionError(SrvXError):
    pass


class NotAuthenticated(SrvXError):
    pass


class NotConnected(SrvXError):
    pass


class QServerSecurityViolation(SrvXError):
    pass


# Core class for communicating with QServer
class SrvX(object):
    def __init__(self, host='127.0.0.1', port=7702, password=None, auth_user=None, auth_password=None, bind=None):
        """Create a core SrvX object for communicating with QServer

        Parameters:

            - str host
            - int port
            - str password
            - str AuthServ user
            - str AuthServ password
            - str ip address to bind to
        """
        # Create a logger for pysrvx
        self.log = getLogger('pysrvx')

        # Create our buffer string which will be used to hold info across
        # responses if needed
        self.response = ''

        # By default we're not authenticated
        self.authenticated = False

        # Settings
        self.host = host
        self.port = port
        self.password = password
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.bind = bind

        # Connect on creation
        self.connect()

    def connect(self):
        """Connect to the QServer"""
        # Create our socket
        self.socket = socket(AF_INET, SOCK_STREAM)

        # If we passed in an ip address to bind to, attempt to bind to it
        if self.bind:
            try:
                self.socket.bind((self.bind, 0))
            except socket_error as err:
                raise ConnectionError("Could not bind socket to %s: %s" % (self.bind, err))

        # Connect to QServer
        self.log.info("Connecting to %s:%i", self.host, self.port)
        try:
            self.socket.connect((self.host, self.port))
        except socket_error as err:
            raise ConnectionError("Could not connect to %s:%i: %s" % (self.host, self.port, err))

        # Send the QServer username and password
        self._send_command('PASS %s' % self.password, True)

        # Authenticate
        self._authenticate(self.auth_user, self.auth_password)

    def _authenticate(self, username, password):
        """Authenticate with AuthServ

        Parameters:

          - str: username
          - str: password
        """
        self.log.debug("Authenticating with AuthServ as %s", username)
        # Send the AuthServ auth request
        response = self._send_command('AuthServ AUTH %s %s' % (username, password))

        # Parse the response
        if response['data'][0] == 'I recognize you.':
            self.log.info('Authenticated with AuthServ')
            self.authenticated = True
        else:
            raise AuthenticationError(response['data'][0])

    def disconnect(self):
        """Disconnect from SrvX"""
        self.socket.close()

    def generate_token(self):
        """Return a token generated from a random number"""
        return 'GS%05d' % randint(0, 65535)

    @staticmethod
    def decode_string(string):
        try:
            return string.decode('UTF-8')
        except UnicodeDecodeError:
            try:
                return string.decode('iso-8859-1')
            except UnicodeDecodeError:
                return string.decode('ascii', 'ignore')

    def get_response(self):
        data = ''
        command_length = 0
        response_done = False
        command_output = False

        # Loop until the response is done
        while not response_done:
            # Append data from the socket into the global buffer
            tmp = self.socket.recv(32768)
            if not tmp:
                raise NotConnected

            # If we've not received the line feed delimiter, keep receiving
            if not tmp.endswith(b'\n'):
                continue

            # Append the response buffer
            self.response += self.decode_string(tmp)

            # Split the content into a list
            lines = self.response.split('\n')

            # Loop through each line in the list
            for line in lines:

                # The line is delimited by spaces
                parts = line.split(' ')

                # If our token matches
                if parts[0] == self.token:
                    self.log.debug('Matched on token %s; response code %s' % (parts[0], parts[1]))

                    # We did not auth with QServer Successfully
                    if parts[1] == 'X':
                        self.log.error('QServer Authentication Failure: %s' % line)
                        self.socket.close()
                        raise AuthenticationError(line)

                    elif parts[1] == 'S':
                        self.log.debug('Got a S packet, processing more')
                        command_length += len(line) + 1
                        command_output = True
                        continue

                    elif parts[1] == 'E':
                        # We've reached the end of the response
                        self.log.debug('Got a E packet, ending response')
                        command_length += len(line) + 1
                        response_done = True
                        command_output = False
                        break

                    else:
                        # We've got something with a token but an unknown response code
                        self.log.warning('Unexpected line: "%s"' % line)
                        command_length += len(line) + 1
                elif command_output:
                    command_length += len(line) + 1
                    data += '%s\n' % line
                else:
                    self.log.warning('Unexpected line: "%s"' % line)
                    command_length += len(line) + 1

        # Remove our command from the response buffer
        self.response = self.response[command_length:]
        self.log.debug('Processed %i bytes leaving %i bytes in the buffer' % (command_length, len(self.response)))

        # Build our response packet
        response = {'data': []}
        lines = data.split('\n')
        for line in lines:

            if 'from' not in response:
                parts = line.split(' ')
                response['from'] = parts[0]

            content = line[line.find(':') + 1:]
            if len(content.rstrip()):
                response['data'].append(content.rstrip())

        # Return the response
        return response

    def god_mode(self, enabled):
        self.log.debug('Toggling god_mode to: %i' % enabled)
        if enabled:
            # Enable helping mode
            self._send_command('chanserv god on')
        else:
            # Disable helping mode
            self._send_command('chanserv god off')

    def _send_command(self, command, no_response=False, hide_arg=None):
        # Check for command injection
        if '\n' in command or '\r' in command:
            raise QServerSecurityViolation

        # Get our token
        self.token = self.generate_token()

        # Put a token infront of the command
        command = '%s %s\n' % (self.token, command)

        if hide_arg is not None:
            # TOKEN NICK COMMAND ARGS...
            tmp = command.split(' ')
            tmp[hide_arg + 2] = '****'
            self.log.debug('Sending: %s' % ' '.join(tmp).encode('UTF-8'))
        else:
            self.log.debug('Sending: %s' % command.encode('UTF-8'))

        # Send the command
        response = None
        try:
            self.socket.send(command.encode('UTF-8'))
            if not no_response:
                response = self.get_response()
        except socket_error as err:
            self.log.warning('Lost connection to srvx: %s', err)
            raise ConnectionError(err)

        # return the response
        return response

    def send_command(self, command, no_response=False, hide_arg=None):
        # If we're not authenticated do not send the command
        if not self.authenticated:
            raise NotAuthenticated

        # Send the command
        return self._send_command(command, no_response, hide_arg)
