"""
OpServ Support

"""
from pysrvx.srvx import SrvX
import re

# Uptime: 10 weeks and 6 days (33269954 lines p...d, CPU time 7106.65u/4144.99s)
STATS_UPTIME_RE = re.compile('Uptime: ([0-9]{1,3}) weeks and ([0-7]) days \
\(([0-9]+) lines processed, CPU time ([0-9.u]+)/([0-9.s]+)\)')


class OpServ(object):


    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise ValueError("Did not pass in a SrvX object")

    def _command(self, command):

        # Run the command in the srvx object
        return self.srvx.send_command('opserv %s' % command)

    def access(self, account, level=None):

        # Get the opserv access level of an account
        if level is None:
            response = self._command('access *%s' % account)
        else:
            response = self._command('access *%s %i' % (account, int(level)))

        # Account SomeAccount has not been registered.
        if response['data'][0].endswith('has not been registered.'):
            return None

        field = 0
        if response['data'][0].endswith('outranks you (command has no effect).'):
            field = 1
        elif response['data'][0] == 'You may not promote another oper above your level.':
            field = 1

        # "*ThiefMaster (account ThiefMaster) has 900 access."
        parts = response['data'][field].split(' ')
        return int(parts[4])

    def addtrust(self, ip, count, duration, reason):

        # Add a trusted host
        response = self._command("addtrust %s %i %s %s" % (ip, int(count), duration, reason))
        return response['data'][0].startswith('Added'), response['data'][0]

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
            elif not state: # Information

                if line[0:11] == 'Created on:': # Created on: .... (1234567890)
                    info['created'] = int(line.split(' (')[1][0:-1])

                elif line[0:6] == 'Modes:': # Modes: [+modes][; bad-word channel]
                    matches = re.match(r"^Modes: (?:(\+[a-zA-Z]+)((?: \S+?)*))?(; bad-word channel)?$", line)
                    if matches is None:
                        self.srvx.log.warning('Unexpected mode line: "%s"',
                                              line)
                        continue

                    info['badword'] = matches.group(3) is not None
                    info['modes'] = matches.group(1) and matches.group(1)[1:] or ''
                    info['key'] = None
                    info['limit'] = None
                    if info['modes']:
                        mode_args = matches.group(2).strip().split(' ')
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
                    self.srvx.log.warning('Unexpected line: "%s"',
                                          line)

            elif state == 1: # Bans

                matches = re.match(r"^(\S+) by (\S+) \(([^)]+)\)$", line)
                if matches is None:
                    self.srvx.log.warning('Unexpected ban line: "%s"' % line)
                    continue

                ban = {'mask': matches.group(1),
                       'by': matches.group(2),
                       'time': matches.group(3)}
                bans.append(ban)

            elif state == 2: # Users

                matches = re.match(r"^ ([@+ ])([^:]+)(?::([0-9]+))? \(([^@]+)@([^)]+)\)$", line)
                if matches is None:
                    self.srvx.log.warning('Unexpected user line: "%s"' % line)
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

    def edittrust(self, ip, count, duration, reason):

        # Update a trusted host
        response = self._command('edittrust %s %i %s %s' % (ip, int(count), duration, reason))
        return response['data'][0].startswith('Updated'), response['data'][0]

    def gtrace_count(self, criteria):

        # Get the number of matching glines
        response = self._command("gtrace count %s" % criteria)
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return 0

        return int(response['data'][0].split(' ')[1])

    def _gline_parse(self, line):

        # The following glines were found:
        # ronald@*.gline.de (issued 28 minutes and 55 seconds ago by cltx, lastmod 7 minutes and 44 seconds ago, expires 1 day and 23 hours, lifetime 6 days and 23 hours): Replace
        # miriam@gline.de (issued 29 minutes and 23 seconds ago by cltx, lastmod 29 minutes and 23 seconds ago, expires 6 days and 23 hours, lifetime 6 days and 23 hours): Very bad Person
        # Found 2 matches.

        # { "OSMSG_GTRACE_FORMAT", "%1$s (issued %2$s ago by %3$s, lastmod %4$s ago, expires %5$s, lifetime %7$s): %6$s" },
        # { "OSMSG_GTRACE_FOREVER", "%1$s (issued %2$s ago by %3$s, lastmod %4$s ago, never expires, lifetime %7$s): %6$s" }, # not used by srvx right now (bug)
        # { "OSMSG_GTRACE_EXPIRED", "%1$s (issued %2$s ago by %3$s, lastmod %4$s ago, expired %5$s ago, lifetime %7$s): %6$s" },

        matches = re.match(r"^(\S+) \(issued ([a-z0-9 ]+) ago by (\S+), lastmod ([a-z0-9<> ]+) ago, (expire[sd]) ([a-z0-9 ]+), lifetime ([a-z0-9 ]+)\)\: (.*)$", line)

        if matches is None:
            self.srvx.log.warning('Unexpected gline line: "%s"' % line)
            return None

        gline = {
            'mask': matches.group(1),
            'issued': matches.group(2),
            'setter': matches.group(3),
            'lastmod': matches.group(4) != '<unknown>' and matches.group(4) or None,
            'expired': matches.group(5) == 'expired',
            'expires': matches.group(6),
            'lifetime': matches.group(7),
            'reason': matches.group(8)
        }

        return gline

    def gtrace_print(self, criteria):

        # Get a list of all do-not-registers
        glines = []

        response = self._command("gtrace print %s" % criteria)
        if response['data'][-1] == 'Nothing matched the criteria of your search.':
            return glines

        for line in response['data'][1:-1]:
            gline = self._gline_parse(line)
            if gline:
                glines.append(gline)

        # Return glines list
        return glines

    def stats_bad(self, name=None):

        # Check if the given (channel) name is bad
        if name:
            response = self._command('stats bad %s' % name)
            # #seks does not contain a bad word.
            # #sex contains a bad word.
            return response['data'][0].split(' ', 1)[1] == 'contains a bad word.'

        # Get a list of all badwords and exempts
        response = self._command('stats bad')
        badwords = []
        exempts = []
        for line in response['data']:
            if line.startswith('Bad words:'):
                badwords += line[11:].split()
            elif line.startswith('Exempted channels:'):
                exempts += line[19:].split()
            else:
                self.srvx.log.warning('Unexpected badword line: "%s"' % line)

        return badwords, exempts

    def stats_email(self, email=None):

        # Check if the given email is banned
        if email:
            response = self._command('stats email %s' % email)
            # somebody@mailinator.com may not be used an email address: trash email
            # somebody@gamesurge.net may be used as an email address.

            if response['data'][0].endswith('may be used as an email address.'):
                return None
            return response['data'][0].split(': ', 1)[1]

        # Get a list of all banned emails
        response = self._command('stats email')
        if response['data'][0] == 'All email addresses are accepted.':
            return []

        emails = {}
        for line in response['data']:
            parts = line.split(': ', 1)
            emails[parts[0]] = parts[1]
        return emails

    def stats_glines(self, ip=None):

        # Get a gline or the gline count (depending on ip)
        response = self._command("stats glines %s" % (ip or ''))

        if ip and response['data'][0].endswith('is not a known G-line.'):
            return None

        if not ip:
            parts = response['data'][0].split(' ')
            return int(parts[2])

        return self._gline_parse(response['data'][0])

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
                self.srvx.log.warning('Unexpected trust line: "%s"' % line)
                continue

            trust = {'ip': matches.group(1),
                     'limit': matches.group(2) != "no limit" and int(matches.group(3)) or 0,
                     'set_time': matches.group(4),
                     'setter': matches.group(5),
                     'expires': matches.group(6),
                     'reason': matches.group(7),
                     'orig': line}
            trusts.append(trust)

        # If we checked a specific ip, we can assume trusts to contain exactly one element
        return ip and trusts[0] or trusts

    def trace(self, action, criteria):

        # Get the number of matching users
        response = self._command('trace %s %s' % (action, criteria))
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return 0
        elif response['data'][0].endswith('is an invalid search criteria.'):
            return 0
        elif response['data'][0].endswith('requires more parameters.'):
            return 0
        elif response['data'][0] == 'You must provide a valid channel name.':
            return 0
        elif response['data'][0].startswith('Invalid criteria:'):
            return 0
        elif response['data'][0].startswith('Channel with name ') and \
             response['data'][0].endswith('does not exist.'):
            return 0

        return int(response['data'][0].split(' ')[1])

    def trace_count(self, criteria):
        return self.trace('count', criteria)

    def trace_gline(self, criteria):
        return self.trace('gline', criteria)

    def trace_kill(self, criteria):
        return self.trace('kill', criteria)

    def trace_print(self, criteria):

        response = self._command('trace print %s' % criteria)
        if response['data'][0] == 'Nothing matched the criteria of your search.':
            return []
        elif response['data'][0].endswith('is an invalid search criteria.'):
            return []
        elif response['data'][0].endswith('requires more parameters.'):
            return []
        elif response['data'][0] == 'You must provide a valid channel name.':
            return []
        elif response['data'][0].startswith('Invalid criteria:'):
            return []

        users = []
        for line in response['data'][1:-1]:
            # Strip off leading space if necessary as it breaks the splitting
            leading_space = ''
            if line[0] == ' ':
                leading_space = ' '
                line = line[1:]

            parts = line.split(' ')
            user = {'account': None}
            if len(parts) > 1:
                user['account'] = parts[1]

            nick, ident_host = parts[0].split('!', 1)
            ident, host = ident_host.split('@', 1)
            user['nick'] = leading_space + nick
            user['ident'] = ident
            user['host'] = host
            users.append(user)

        return users

    def stats_uptime(self):
        """Performs a stats update and returns a tuple of data.

        :returns: Tuple of uptime days, weeks, lines processed, cpu time
        """
        # Get a gline or the gline count (depending on ip)
        response = self._command("stats uptime")
        return  STATS_UPTIME_RE.match(response['data'][0]).groups()
