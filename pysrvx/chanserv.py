"""
ChanServ support

"""
from pysrvx.srvx import SrvX
from re import match


class ChanServ(object):

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise ValueError("Did not pass in a SrvX object")

    def _command(self, command):

        # Send the command through srvx
        return self.srvx.send_command('chanserv %s' % command)

    def access(self, channel, account):

        # Access of an account in a channel
        response = self._command('access %s *%s' % (channel, account))

        if response['data'][0] == \
           'You must provide the name of a channel that exists.':
            return 0

        if response['data'][0].find('has not been registered.') != -1:
            return 0

        access = 0
        if response['data'][0].startswith('%s has access ' % account):
            parts = response['data'][0].split(' ')
            access = int(parts[3])
        # Negative access if user is suspended
        if len(response['data']) > 1 and \
           response['data'][-1].endswith('has been suspended.'):
            access *= -1

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

        # Run adduser, if the user has access & force is true we clvl him
        response = self._command('adduser %s *%s %s' % \
                                 (channel, account, level))

        if force and response['data'][0].find('is already on') != -1:
            return self.clvl(channel, account, level)

        return response['data'][0].startswith('Added'), response['data'][0]

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

        return response['data'][0].find('now has access') != -1, \
               response['data'][0]

    def csuspend(self, channel, duration, reason, modify=False):

        # Suspend channel or modify channel suspended
        if modify:
            response = self._command('csuspend %s !%s %s' % \
                                     (channel, duration, reason))
            # When modifying a suspension srvx doesn't reply anything
            if not len(response['data']):
                return True, ''
        else:
            response = self._command('csuspend %s %s %s' % \
                                     (channel, duration, reason))

        return response['data'][0].endswith(\
            'has been temporarily suspended.'), response['data'][0]

    def cunsuspend(self, channel):

        # Unsuspend channel
        response = self._command('cunsuspend %s' % channel)

        return response['data'][0].endswith('has been restored.'),\
               response['data'][0]

    def deluser(self, channel, account, level=None, strict=False):

        # Delete user from channel user list
        # If a level is given, the user must have this level to be deleted
        # If 'strict' is set, the deletion is only considered successful
        # if the user was on the userlist before

        if level:
            response = self._command('deluser %s %s *%s' % \
                                     (channel, level, account))
        else:
            response = self._command('deluser %s *%s' % \
                                     (channel, account))

        if not strict and response['data'][0].find('lacks access to') != -1:
            return True, response['data'][0]

        return response['data'][0].startswith('Deleted '), response['data'][0]

    def _dnrsearch_parse(self, response, silent=False):

        # Get a list of all do-not-registers
        dnrs = []

        if response['data'][-1] == 'Nothing matched the criteria of your search.':
            return dnrs

        # The following do-not-registers were found:
        # *testxyz is do-not-register (set 26 Feb 2007 by ThiefMaster): kiddie
        # #xy*z is do-not-register (set 26 Feb 2007 by ThiefMaster): lalala that's just a test
        # #m*rt*n is do-not-register (set 14 Apr 2010 by cltx; expires 21 Apr 2010): Very special test dnr
        # Found 3 matches.

        if response['data'][0] == 'The following do-not-registers were found:':
            del response['data'][0]

        matches = match(r'^Found \d+ matches.$', response['data'][-1])
        if matches is not None:
            del response['data'][-1]

        for line in response['data']:
            matches = match(r"^((?:\*|\#)[^\s]+) is do-not-register \(set (\d+\
 \w{3} \d{4}) by ([^\s\;\)]+)(?:\; expires (\d+ \w{3} \d{4})){0,1}\)\:\s(.*)$",
                            line)

            if matches is None:
                if not silent:
                    self.srvx.log.warning('Unexpected dnr line: "%s"', line)
                continue

            dnr = {'glob': matches.group(1),
                   'set_time': matches.group(2),
                   'setter': matches.group(3),
                   'expires': matches.group(4),
                   'reason': matches.group(5),
                   'orig': line}
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
        if response['data'][0] == \
           "Nothing matched the criteria of your search.":
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

    def giveownership(self, channel, account, force=False):

        # Chanegs Ownership of a channel
        response = self._command('giveownership %s *%s %s' % \
                                 (channel, account, force and 'FORCE' or ""))
        return response['data'][0].find(\
            'Ownership of %s has been transferred' % channel) != -1, \
               response['data'][0]

    def _info_check_dnr(self, line):
        matches = match(r'^((?:\*|\#)[^\s]+) is do-not-register \(set (\d+ \w\
{3} \d{4}) by ([^\s\;\)]+)(?:\; expires (\d+ \w{3} \d{4})){0,1}\)\:\s(.*)$',
                        line)

        if matches is None:
            return False

        dnr = {'glob': matches.group(1),
               'set_time': matches.group(2),
               'setter': matches.group(3),
               'expires': matches.group(4),
               'reason': matches.group(5),
               'orig': line}
        return dnr

    def info(self, channel):

        # Send our command to ChanServ
        response = self._command('info %s' % channel)

        if response['data'][0] == \
           'You must provide the name of a channel that exists.':
            return None
        elif response['data'][0].endswith(\
            'has not been registered with ChanServ.'):
            return None

        # Build the initial dictionary
        info = {'channel': response['data'][0].split(' ')[0],
                'notes': {},
                'owners': [],
                'registrar': None,
                'dnrs': [],
                'suspended': False,
                'suspensions': []}

        suspensions = False
        for line in response['data'][1:]:

            # Check for dnr line
            dnr = self._info_check_dnr(line)
            if dnr:
                info['dnrs'].append(dnr)
                continue

            # Check for suspension
            if line == info['channel'] + ' is suspended:':
                info['suspended'] = True
                suspensions = True
                continue
            elif line.startswith('Suspension history for'):
                suspensions = True
                continue

            # If we had a suspension header, everything is suspension-related
            if suspensions:
                info['suspensions'].append(line.strip())
                continue

            # Deal with regular 'key: value' pairs
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip()

            if key == 'Default Topic':
                info['default_topic'] = value or None

            elif key == 'Mode Lock':
                info['mode_lock'] = (value != 'None') and value or None

            elif key == 'Record Visitors':
                info['record_visitors'] = int(value)

            elif key == 'Owner':
                info['owners'].append(value)

            elif key == 'Total User Count':
                info['user_count'] = int(value)

            elif key == 'Ban Count':
                info['ban_count'] = int(value)

            elif key == 'Visited':
                info['visited'] = value[:-1] # strip trailing dot

            elif key == 'Registered':
                info['registered'] = value[:-1] # strip trailing dot

            elif key == 'Registrar':
                info['registrar'] = value

            else:
                # Horrible, this could also be an unknown key..
                # but we cannot distinguish between that without checking
                # the position
                info['notes'][key] = value

        return info

    def mlist(self, channel):

        # Use the generic users function
        return self.users(channel, 'mlist')

    def mode(self, channel, modes):

        # Set mode of channel
        response = self._command('mode %s %s' % (channel, modes))

        return response['data'][0].startswith('Channel modes are now')

    def notes(self, channel):
        response = self._command('note %s' % channel)

        if response['data'][0] == 'You must provide the name of a channel ' + \
            'that exists.':
            return None
        elif response['data'][0].endswith('has not been registered with ' + \
            'ChanServ.'):
            return None

        if response['data'][0].startswith('There are no (visible) notes for'):
            return {}

        notes = {}
        for line in response['data'][1:-1]:
            matches = match(r'^(\S+) \(set by ([^)]+)\)\: (.+)$', line)
            if matches is None:
                self.srvx.log.warning('Unexpected mode line: "%s"' % line)
                continue

            note = dict()
            note['setter'] = matches.group(2)
            note['text'] = matches.group(3)
            notes[matches.group(1)] = note

        return notes

    def note(self, channel, type, text=None):

        # Run command
        if text:
            response = self._command('note %s %s %s' % (channel, type, text))
        else:
            response = self._command('note %s %s' % (channel, type))

        if response['data'][0].startswith('Replaced old %s note on' % type):
            del response['data'][0]

        if response['data'][0].startswith('Note %s set in channel' % type):
            return True

        if response['data'][0] == 'Note type %s does not exist.' % type:
            return False

        if response['data'][0].startswith('Channel %s does not have a note' %
            channel):
            return None

        matches = match(r'^(\S+) \(set by ([^)]+)\)\: (.+)$',
            response['data'][-1])
        if matches is not None:
            return matches.group(3)

        return False

    def say(self, channel, message):

        # Send the say command, we don't care about the response
        self._command('say %s %s' % (channel, message))

    def olist(self, channel):

        # Use the generic users function
        return self.users(channel, 'olist')

    def plist(self, channel):

        # Use the generic users function
        return self.users(channel, 'plist')

    def register(self, channel, account, force=False):

        # Register a channel
        response = self._command('register %s *%s %s' %
            (channel, account, force and 'FORCE' or ''))

        # We first check for dnrs since they can end with arbitrary strings
        # and would make checking for other things harder
        dnrs = self._dnrsearch_parse(response, silent=True)
        if dnrs:
            return False, {'reason': 'dnr', 'dnrs': dnrs}, None

        line = response['data'][0]
        if line.endswith('illegal channel, and cannot be registered.'):
            return False, {'reason': 'illegal'}, line

        if line == 'has not been registered.':
            return False, {'reason': 'no_account'}, line

        if line.endswith('is registered to someone else.'):
            return False, {'reason': 'registered'}, line

        if line == 'You must provide a valid channel name.':
            return False, {'reason': 'bad_name'}, line

        if line.find('owns enough channels') != -1:
            return False, {'reason': 'too_many'}, line

        if line.find('now has ownership of') or \
            line.find('now have ownership of'):
            return True, None, line

    def users(self, channel, list_type='users'):

        # List to put users in
        users = []

        # Get the userlist data
        response = self._command('%s %s' % (list_type, channel))

        if response['data'][0] == 'You must provide the name of a channel that exists.':
            return users

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
