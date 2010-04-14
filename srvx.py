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
            self.authenticated = True
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
        command_output = False

        # Loop until the response is done
        while not response_done:

            # Append data from the socket into the global buffer
            self.response += connection.recv(32768)
            if self.response[-1] != '\n':
                continue

            # Split the content into a list
            lines = self.response.split('\n')

            # Loop through each line in the list
            for line in lines:

                parts = line.split(' ')
                token = parts[0]

                # If it finds the token
                if token == self.token:

                    response_code = parts[1]
                    #logging.debug('Matched on token %s; response code %s' % (self.token, response_code))

                    # We did not auth with QServer Successfully
                    if response_code == 'X':
                        command_length += len(line)
                        logging.error('QServer Authentication Failure')
                        connection.close()
                        connection = None
                        raise QServerAuthenticationFailure()

                    elif response_code == 'S':
                        #logging.debug('Got a S packet, processing more')
                        command_length += len(line) + 1
                        command_output = True
                        continue

                    elif response_code == 'E':
                        # We've reached the end of the response
                        #logging.debug('Got a E packet, ending response')
                        command_length += len(line) + 1
                        response_done = True
                        command_output = False
                        break

                    else:
                        # We've got something with a token but an unknown response code
                        logging.warning('Unexpected line: "%s"' % line)
                        command_length += len(line) + 1
                elif command_output:
                    command_length += len(line) + 1
                    data += '%s\n' % line
                else:
                    logging.warning('Unexpected line: "%s"' % line)
                    command_length += len(line) + 1


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
            if len(content.rstrip()):
                response['data'].append(content.rstrip())

        # Return the response
        return response

    def god_mode(self, enabled):

        logging.debug('Toggling god_mode to: %i' % enabled)
        if enabled:
            # Enable helping mode
            self._send_command('chanserv god on')
        else:
            # Disable helping mode
            self._send_command('chanserv god off')

    def _send_command(self, command, no_response=False, hide_arg=None):

        global connection

        # Check for command injection
        if command.find('\n') != -1 or command.find('\r') != -1:
            raise QServerSecurityViolation

        # Get our token
        self.token = self.generate_token()

        # Put a token infront of the command
        command = '%s %s\n' % (self.token, command)

        if hide_arg is not None:
            # TOKEN NICK COMMAND ARGS...
            tmp = command.strip().split(' ')
            tmp[hide_arg + 2] = '****'
            logging.debug('Sending: %s' % ' '.join(tmp))
        else:
            logging.debug('Sending: %s' % command.strip())

        # Send the command
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

    def _command(self, command, hide_arg=None):

        # Run the command in the srvx object
        return self.srvx._send_command('authserv %s' % command, hide_arg=hide_arg)

    def accountinfo(self, account):

        # Retrieve account info
        response = self._command('accountinfo *%s' % account)

        # Bail out if account does not exist
        if response['data'][0].split(' ')[3] == 'not':
            return None

        # Get account name "Account information for NAME:"
        info = {'account': response['data'][0].split(' ')[3][0:-1],
                'vacation': False,
                'notes': [],
                'nicks': [],
                'hostmasks': [],
                'channels': {},
                'dnr': None,
                'epithet': None,
                'fakeident': None,
                'fakehost': None,
                'cookie' : None}

        # Loop over actual account information
        for line in response['data'][1:]:
            parts = line.split(':', 1)
            if len(parts) < 2:
                if parts[0].strip() == 'On vacation.':
                    info['vacation'] = True
                else:
                    logging.error('Odd accountinfo response: %s' % line)
                continue

            else:
                key = parts[0].strip()
                value = parts[1].strip()

                if key == 'Registered on':
                    info['registered'] = value

                elif key == 'Last seen':
                    info['seen'] = (value != 'Right now!') and value or 0

                elif key == 'Infoline':
                    info['infoline'] = (value != 'None') and value or None

                elif key == 'Karma':
                    info['karma'] = int(value)

                elif key == 'Email address':
                    info['email'] = (value != 'Not set.') and value or None

                elif key == 'Account ID':
                    info['id'] = int(value)

                elif key == 'Notes' and value == 'None':
                    pass

                elif key == 'Flags':
                    info['flags'] = (value[0] == '+') and value[1:] or ''

                elif key == 'Last quit hostmask':
                    info['lqh'] = (value != 'Unknown') and value or None

                elif key == 'Epithet':
                    info['epithet'] = (value != 'None') and value or None

                elif key == 'Fake ident':
                    info['fakeident'] = value

                elif key == 'Fake host':
                    parts = value.rsplit('@', 1)
                    if len(parts) == 1:
                        info['fakehost'] = parts[0]
                    else:
                        info['fakeident'] = parts[0]
                        info['fakehost'] = parts[1]

                elif key == 'Hostmask(s)':
                    if value != 'None':
                        info['hostmasks'] += value.split(' ')

                elif key == 'Channel(s)':
                    if value != 'None':
                        channels = value.split(' ')
                        for channel in channels:
                            access, name = channel.split(':', 1)
                            info['channels'][name] = int(access)

                elif key == 'Current nickname(s)':
                    info['nicks'] += value.split(' ')

                elif key == 'Cookie':
                    matches = re.match(r"There is currently an? ([a-z ]+) cookie issued", value)
                    if matches is None:
                        logging.debug('Unexpected cookie line: "%s"' % line)
                        continue

                    info['cookie'] = matches.group(1)

                elif key[0:5] == 'Note ':
                    matches = re.match(r"^Note ([0-9]+) \(([a-z0-9 ]+) ago by ([^,]+)(?:, expires ([^)]+))?\)$", key)
                    if matches is None:
                        logging.debug('Unexpected note line: "%s"' % line)
                        continue

                    note = {'id': int(matches.group(1)),
                            'set_time': matches.group(2),
                            'setter': matches.group(3),
                            'expires': matches.group(4),
                            'text': value}

                    info['notes'].append(note)

                elif key.startswith('Do-not-register'):
                    info['dnr'] = value

                else:
                    logging.warning('Unknown accountinfo key: "%s" (%s)' % (key, value))

        return info

    def checkemail(self, account, email):

        # Check if the account email is the given one
        response = self._command('checkemail *%s %s' % (account, email))
        return response['data'][0] == 'Yes.'

    def checkpass(self, account, password):

        # Check to see if the account and password are valid in returning bool
        response = self._command('checkpass %s %s' % (account, password), hide_arg=2)
        return response['data'][0] == 'Yes.'

    def oregister(self, account, password, email=None, mask=None):

        # Register a new AuthServ account
        response = self._command('oregister %s %s %s %s' % (account, password, mask and mask or '*', email and email or ""), hide_arg=2)
        return response['data'][0] == 'Account has been registered.', response['data'][0]

    def ounregister(self, account, force=False):

        # Remove an Account from the network
        response = self._command('ounregister *%s %s' % (account, force and 'FORCE' or ""))
        return response['data'][0].find('been unregistered.') != -1, response['data'][0]

    def rename(self, account, newaccount):

        # Rename Account
        response = self._command('rename *%s %s' % (account, newaccount))
        return response['data'][0].find('account name has been changed') != -1, response['data'][0]

    def search_count(self, criteria):

        # Get the number of matching users
        response = self._command("search count %s" % criteria)
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return 0

        return int(response['data'][0].split(' ')[1])

    def search_print(self, criteria):

        # Get the matching users
        users = []
        response = self._command("search print %s" % criteria)

        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return users

        for line in response['data'][1:-1]:
            parts = line.split(' ', 1)
            users.append(parts[1])

        return users


class ChanServ():

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise InvalidSrvXObject

    def _command(self, command):

        # Send the command through srvx
        return self.srvx.send_command('chanserv %s' % command)

    def access(self, channel, account):

        # Access of an account in a channel
        response = self._command('access %s *%s' % (channel, account))

        if response['data'][0] == 'You must provide the name of a channel that exists.':
            return 0

        if response['data'][0].find('has not been registered.') != -1:
            return 0

        access = 0
        if response['data'][0].startswith('%s has access ' % account):
            parts = response['data'][0].split(' ')
            access = int(parts[3])
        # Negative access if user is suspended
        if len(response['data']) > 1 and response['data'][-1].endswith('has been suspended.'):
            access = access * -1
        return access

    def addcoowner(self, channel, account, force=False):

        # Use the generic adduser function
        return self.adduser(channel, account, 'coowner', force)

    def addmaster(self, channel, account, force=False):

        # Use the generic adduser function
        return self.adduser(channel, account, 'master', force)

    def addaddop(self, channel, account, force=False):

        # Use the generic adduser function
        return self.adduser(channel, account, 'op', force)

    def addowner(self, channel, account, force=False):

        # Use the generic adduser function
        return self.adduser(channel, account, 'owner', force)

    def addpeon(self, channel, account, force=False):

        # Use the generic adduser function
        return self.adduser(channel, account, 'peon', force)

    def adduser(self, channel, account, level, force=False):

        # Run adduser, if the user has already access and force is true we clvl him
        response = self._command('adduser %s *%s %s' % (channel, account, level))

        if force and response['data'][0].find('is already on') != -1:
            return self.clvl(channel, account, level)

        return response['data'][0].find('Added') != -1, response['data'][0]

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
        for line in response['data'][1:len(response['data']) - 1]:

            # Append the dictionary for the row to the ban list
            bans.append({'mask': line[c1:c2].strip(),
                         'set_by': line[c2:c3 - 1].strip(),
                         'triggered': line[c3:c4 - 1].strip(),
                         'reason': line[c4:].strip()})

        # Remove the ban list dictionary
        return bans

    def clist(self, channel):

        # Use the generic users function
        return self.users(channel, 'clist')

    def clvl(self, channel, account, level, force=False):

        # Run clvl, if the user has no access and force is true we adduser him
        response = self._command('clvl %s *%s %s' % (channel, account, level))

        if force and response['data'][0].find('lacks access to') != -1:
            return self.adduser(channel, account, level)

        return response['data'][0].find('now has access') != -1, response['data'][0]

    def csuspend(self, channel, duration, reason, modify=False):

        # Suspend channel or modify channel suspended
        if modify:
            response = self._command('csuspend %s !%s %s' % (channel, duration, reason))
            # When modifying a suspension srvx doesn't reply anything
            if len(response['data']) == 0:
                return True, ''
        else:
            response = self._command('csuspend %s %s %s' % (channel, duration, reason))

        return response['data'][0].find('has been temporarily suspended.') != -1, response['data'][0]

    def cunsuspend(self, channel):

        # Unsuspend channel
        response = self._command('cunsuspend %s' % channel)

        return response['data'][0].find('has been restored.') != -1, response['data'][0]

    def deluser(self, channel, account, level=None, strict=False):

        # Delete user from channel user list
        # If a level is given, the user must have exactly this level to be deleted
        # If 'strict' is set, the deletion is only considered successful if the user was on the userlist before

        if level:
            response = self._command('deluser %s %s *%s' % (channel, level, account))
        else:
            response = self._command('deluser %s *%s' % (channel, account))

        if not strict and response['data'][0].find('lacks access to') != -1:
            return True, response['data'][0]

        return response['data'][0].startswith('Deleted '), response['data'][0]

    def _dnrsearch_parse(self, response):

        # Get a list of all do-not-registers
        dnrs = []

        if response['data'][-1] == 'Nothing matched the criteria of your search.':
            return dnrs

        # The following do-not-registers were found:
        # *testxyz is do-not-register (set 26 Feb 2007 by ThiefMaster): kiddie
        # #xy*z is do-not-register (set 26 Feb 2007 by ThiefMaster): lalala that's just a test
        # #m*rt*n is do-not-register (set 14 Apr 2010 by cltx; expires 21 Apr 2010): Very special test dnr
        # Found 3 matches.

        matches = re.match(r'^Found \d+ matches.$', response['data'][-1])
        if matches is not None:
            del response['data'][-1]

        for line in response['data'][1:]:
            matches = re.match(r"^((?:\*|\#)[^\s]+) is do-not-register \(set (\d+ \w{3} \d{4}) by ([^\s\;\)]+)(?:\; expires (\d+ \w{3} \d{4})){0,1}\)\:\s(.*)$", line)

            if matches is None:
                logging.debug('Unexpected dnr line: "%s"' % line)
                continue

            dnr = {'glob': matches.group(1),
                   'set_time': matches.group(2),
                   'setter': matches.group(3),
                   'expires': matches.group(4),
                   'reason': matches.group(5)}
            dnrs.append(dnr)

        # Return dnr list
        return dnrs

    def dnr(self, channel=''):

        # Send our command to ChanServ
        response = self._command('noregister %s' % channel)

        # Parse it
        return self._dnrsearch_parse(response)

    def dnrsearch_count(self, criteria):

        # Send our command to ChanServ
        response = self._command('dnrsearch count %s' % criteria)

        # Parse it
        if response['data'][0] == "Nothing matched the criteria of your search.":
            return 0

        parts = response['data'][0].split(' ')
        return int(parts[1])

    def dnrsearch_print(self, criteria):

        # Send our command to ChanServ
        response = self._command('dnrsearch print %s' % criteria)

        # Parse it
        return self._dnrsearch_parse(response)

    def dnrsearch_remove(self, criteria):

        # Send our command to ChanServ
        response = self._command('dnrsearch count %s' % criteria)

        # Parse it
        if response['data'][0] == "Nothing matched the criteria of your search.":
            return 0

        parts = response['data'][-1].split(' ')
        return int(parts[1])

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

    def mode(self, channel, modes):

        # Set mode of channel
        response = self._command('mode %s %s' % (channel, modes))

        return response['data'][0].startswith('Channel modes are now')

    def say(self, channel, message):

        # Send the say command, we don't care about the response
        self._command('say %s %s' % (channel, message))

    def olist(self, channel):

        # Use the generic users function
        return self.users(channel, 'olist')

    def plist(self, channel):

        # Use the generic users function
        return self.users(channel, 'plist')

    def users(self, channel, list_type='users'):

        # List to put users in
        users = []

        # Get the userlist data
        response = self._command('%s %s' % (list_type, channel))

        # Get the column positions
        c1 = 0
        c2 = response['data'][1].find('Account')
        c3 = response['data'][1].find('Last Seen')
        c4 = response['data'][1].find('Status')

        # Loop through the response from the 3rd line
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

    def access(self, account, level=None):

        # Get the opserv access level of an account
        if level is None:
            response = self._command('access *%s' % account)
        else:
            response = self._command('access *%s %i' % (account, int(level)))

        # "*ThiefMaster (account ThiefMaster) has 900 access."
        # Account SomeAccount has not been registered.
        parts = response['data'][0].split(' ')
        if parts[3] == 'not':
            return None
        return int(parts[4])

    def addtrust(self, ip, count, duration, reason):

        # Add a trusted host
        response = self._command("addtrust %s %i %s %s" % (ip, int(count), duration, reason))
        return response['data'][0][0:5] == 'Added', response['data'][0]

    def chaninfo(self, channel):

        # Send our command to OpServ; always request full userlist
        response = self._command('chaninfo %s users' % channel)

        if response['data'][0] == 'You must provide the name of a channel that exists.':
            return None

        # Build the initial dictionary
        info = {'channel': response['data'][0].split(' ')[0]}
        bans = []
        users = []

        # States: 0 = info, 1 = bans, 2 = users
        state = 0
        # Loop through the remaining lines and build a dictionary of values
        for line in response['data'][1:]:
            if line[0:4] == 'Bans':
                state = 1
            elif line[0:5] == 'Users':
                state = 2
            elif state == 0: # Information

                if line[0:11] == 'Created on:': # Created on: .... (1234567890)
                    info['created'] = int(line.split(' (')[1][0:-1])

                elif line[0:6] == 'Modes:': # Modes: [+modes][; bad-word channel]
                    matches = re.match(r"^Modes: (?:(\+[a-zA-Z]+)((?: \S+?)*))?(; bad-word channel)?$", line)
                    if matches is None:
                        logging.debug('Unexpected mode line: "%s"' % line)
                        continue

                    info['badword'] = matches.group(3) is not None
                    info['modes'] = matches.group(1) and matches.group(1)[1:] or ''
                    info['key'] = None
                    info['limit'] = None
                    if info['modes']:
                        mode_args = matches.group(2).strip().split(' ')
                        arg = 0
                        for mode in info['modes']:
                            if mode == 'l':
                                info['limit'] = int(mode_args.pop(0))
                            elif mode == 'k':
                                info['key'] = mode_args.pop(0)

                elif line[0:5] == 'Topic': # Topic (set by [...], Tue Jan 19 06:27:40 2010): [...]
                    matches = re.match(r"^Topic \(set by ([^,]*), ([^)]+)\): (.*)$", line)
                    if matches is None:
                        continue
                    info['topic_by'] = matches.group(1)
                    info['topic_time'] = matches.group(2)
                    info['topic'] = matches.group(3)
                else:
                    logging.debug('Unexpected line: "%s"' % line)

            elif state == 1: # Bans

                matches = re.match(r"^(\S+) by (\S+) \(([^)]+)\)$", line)
                if matches is None:
                    logging.debug('Unexpected ban line: "%s"' % line)
                    continue

                ban = {'mask': matches.group(1),
                       'by': matches.group(2),
                       'time': matches.group(3)}
                bans.append(ban)

            elif state == 2: # Users

                matches = re.match(r"^ ([@+ ])([^:]+)(?::([0-9]+))? \(([^@]+)@([^)]+)\)$", line)
                if matches is None:
                    logging.debug('Unexpected user line: "%s"' % line)
                    continue

                user = {'nick': matches.group(2),
                        'ident': matches.group(4),
                        'host': matches.group(5),
                        'op': matches.group(1) == '@',
                        'voice': matches.group(1) == '+',
                        'oplevel': matches.group(3) and int(matches.group(3))}

                users.append(user)

        info['bans'] = bans
        info['users'] = users

        return info

    def csearch_count(self, criteria):

        # Get the number of matching channels
        response = self._command("csearch count %s" % criteria)
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return 0

        return int(response['data'][0].split(' ')[1])

    def csearch_print(self, criteria):

        # Get the matching channels
        channels = {}
        response = self._command("csearch print %s" % criteria)

        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return channels

        for line in response['data'][1:-1]:
            parts = line.split(' ', 1)
            channels[parts[0]] = parts[1]

        return channels

    def deltrust(self, ip):

        # Remove a trusted host
        response = self._command("deltrust %s" % ip)
        return response['data'][0] == 'Removed trusted hosts from the trusted-hosts list.'

    def stats_trusted(self, ip=None):

        # Get a list of trusted hosts
        trusts = []
        response = self._command("stats trusted %s" % (ip or ''))

        if ip and response['data'][0].split(' ', 1)[1] == 'does not have a special trust.':
            return None

        # List of trusted hosts:
        # 192.168.2.1 (limit 10; set 2 minutes and 41 seconds ago by cltx; expires 23 hours and 57 minutes: test bla)
        # 192.168.2.2 (no limit; set 2 minutes and 40 seconds ago by cltx; expires never: test bla)
        begin = 1
        if ip is not None: # "List of trusted hosts:" is only shown if not ip is given
            begin = 0

        for line in response['data'][begin:]:
            matches = re.match(r"^(\S+) \((limit (\d+)|no limit); set ([a-z0-9 ]+) ago by (\S+); expires ([^:]+): (.+)\)$", line)
            if matches is None:
                logging.debug('Unexpected trust line: "%s"' % line)
                continue

            trust = {'ip': matches.group(1),
                     'limit': matches.group(2) != "no limit" and int(matches.group(3)) or 0,
                     'set_time': matches.group(4),
                     'setter': matches.group(5),
                     'expires': matches.group(6),
                     'reason': matches.group(7)}
            trusts.append(trust)

        # If we checked a specific ip, we can assume trusts to contain exactly one element
        return ip and trusts[0] or trusts


# Exceptions
class AuthServAuthenticationFailure(Exception):
    pass

class QServerAuthenticationFailure(Exception):
    pass

class InvalidSrvXObject(Exception):
    pass

class SrvXNotAuthenticated(Exception):
    pass

class QServerSecurityViolation(Exception):
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
        parser.print_help()

    # Make sure the auth string is in foo:bar format
    auth = options.auth.split(':')
    if len(auth) < 2:
        print 'Error: invalid authserv credentials'
        parser.print_help()

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
        if len(args) == 2:
            print function()
        elif len(args) == 3:
            print function(args[2])
        elif len(args) == 4:
            print function(args[2], args[3])
        elif len(args) == 5:
            print function(args[2], args[3], args[4])
        elif len(args) == 6:
            print function(args[2], args[3], args[4], args[5])
