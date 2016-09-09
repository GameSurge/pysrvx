import re


class AuthServ(object):
    def __init__(self, srvx):
        self.srvx = srvx

    def _command(self, command, hide_arg=None):
        return self.srvx.send_command('authserv %s' % command, hide_arg=hide_arg)

    def accountinfo(self, account, nickname=False):
        # Retrieve account info
        if nickname:
            response = self._command('accountinfo %s' % account)
        else:
            response = self._command('accountinfo *%s' % account)

        # Bail out if account does not exist
        if response['data'][0].endswith('has not been registered.'):
            return None

        if response['data'][0].find('must first authenticate') > 0:
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
                'cookie': None}

        # Loop over actual account information
        for line in response['data'][1:]:
            parts = line.split(':', 1)
            if len(parts) < 2:
                if parts[0].strip() == 'On vacation.':
                    info['vacation'] = True
                else:
                    self.srvx.log.error('Odd accountinfo response: %s',
                                        line)
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
                        self.srvx.log.warning('Unexpected cookie line: "%s"', line)
                        continue

                    info['cookie'] = matches.group(1)

                elif key[0:5] == 'Note ':
                    matches = re.match(r"^Note ([0-9]+) \(([a-z0-9 ]+) ago by ([^,]+)(?:, expires ([^)]+))?\)$", key)
                    if matches is None:
                        self.srvx.log.warning('Unexpected note line: "%s"', line)
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
                    self.srvx.log.warning('Unknown accountinfo key: "%s" (%s)',
                                          key, value)

        return info

    def checkemail(self, account, email):
        # Check if the account email is the given one
        response = self._command('checkemail *%s %s' % (account, email))
        return response['data'][0] == 'Yes.'

    def checkid(self, ids):
        # Check given account IDs and return their account names if they exist
        if not isinstance(ids, list):
            response = self._command('checkid %s' % ids)
            parts = response['data'][0].split(' ')
            return parts[1] != '*' and parts[1] or None

        accounts = {}
        for chunk in (ids[pos:pos + 20] for pos in range(0, len(ids), 20)):
            response = self._command('checkid %s' % ' '.join(map(str, chunk)))
            for line in response['data']:
                parts = line.split(' ')
                accounts[int(parts[0])] = parts[1] != '*' and parts[1] or None

        return accounts

    def checkpass(self, account, password, verbose=False):
        # Check to see if the account and password are valid in returning bool
        response = self._command('checkpass %s %s' % (account, password),
                                 hide_arg=2)
        msg = response['data'][0]
        valid = (msg == 'Yes.')
        if not verbose:
            return valid
        reason = None
        if not valid:
            if msg == 'No.':
                reason = 'invalid_password'
            elif msg.endswith('has not been registered.'):
                reason = 'invalid_account'
            else:
                reason = 'unknown'
        return {'valid': valid, 'reason': reason}

    def oregister(self, account, password, email=None, mask=None):
        # Register a new AuthServ account
        response = self._command('oregister %s %s %s %s' %
                                 (account, password, mask and mask or '*',
                                  email and email or ""), hide_arg=2)
        return response['data'][0] == 'Account has been registered.', response['data'][0]

    def oset(self, account, key=None, value=None):
        keys = ['color', 'email', 'info', 'language', 'privmsg', 'tablewith',
                'width', 'maxlogins', 'password', 'flags', 'level', 'epithet',
                'title', 'fakehost']

        if key and key.lower() not in keys:
            raise ValueError('Invalid setting')

        # oset some value or get it or get them all
        if key and key.lower() == 'password' and value:
            response = self._command('oset *%s %s %s' % (account, key or "", value or ""), hide_arg=3)
        else:
            response = self._command('oset *%s %s %s' % (account, key or "", value or ""))

        if response['data'][0].endswith('outranks you (command has no effect).'):
            return False, response['data'][0]

        if response['data'][0].endswith('is an invalid account setting.'):
            return False, response['data'][0]

        if response['data'][0].endswith('has not been registered.'):
            return False, response['data'][0]

        if response['data'][0].endswith('does not exist.'):
            return False, response['data'][0]

        if response['data'][0] == 'AuthServ account settings:':
            sets = {}
            for line in response['data'][1:]:
                c2 = line.find(':')
                if line[c2 + 1:].strip() == 'Not set.':
                    sets[line[0:c2].lower()] = None
                else:
                    sets[line[0:c2].lower()] = line[c2 + 1:].strip()
            return True, sets

        if ':' not in response['data'][0]:
            return False, response['data'][0]

        parts = response['data'][0].split(':')
        if parts[0].lower() not in keys:
            return False, response['data'][0]

        if parts[1].strip() == 'Not set.':
            return True, None

        return True, parts[1].strip()

    def oset_email(self, account, value=None):
        return self.oset(account, 'email', value)

    def oset_flags(self, account, value=None):
        return self.oset(account, 'flags', value)

    def oset_level(self, account, value=None):
        return self.oset(account, 'level', value)

    def oset_password(self, account, value=None):
        return self.oset(account, 'password', value)

    def ounregister(self, account, force=False):
        # Remove an account from the network
        response = self._command('ounregister *%s %s' % (account, force and 'FORCE' or ""))
        return 'been unregistered.' in response['data'][0], response['data'][0]

    def rename(self, account, newaccount):
        response = self._command('rename *%s %s' % (account, newaccount))
        return 'account name has been changed' in response['data'][0], response['data'][0]

    def search_count(self, criteria):
        # Get the number of matching users
        response = self._command("search count %s" % criteria)
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return 0
        elif response['data'][0].endswith('is an invalid search criteria.'):
            return 0
        elif response['data'][0].endswith('requires more parameters.'):
            return 0
        return int(response['data'][0].split(' ')[1])

    def search_print(self, criteria):
        # Get the matching users
        users = []
        response = self._command("search print %s" % criteria)

        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return []
        elif response['data'][0].endswith('is an invalid search criteria.'):
            return []
        elif response['data'][0].endswith('requires more parameters.'):
            return []

        for line in response['data'][1:-1]:
            parts = line.split(' ', 1)
            users.append(parts[1])

        return users

    def status(self):
        return self._command("status")
