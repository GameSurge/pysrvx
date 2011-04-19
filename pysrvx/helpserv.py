"""
HelpServ Support

"""
from pysrvx.srvx import SrvX


class HelpServ(object):

    def __init__(self, srvx):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise ValueError("Did not pass in a SrvX object")

    def _command(self, command):

        # Send the command through srvx
        return self.srvx.send_command('opserv helpserv %s' % command)


class HelpServBot(object):

    def __init__(self, srvx, botname):

        # Make sure that a srvx object was passed in
        if isinstance(srvx, SrvX):
            self.srvx = srvx
        else:
            raise ValueError("Did not pass in a SrvX object")

        # Define my name
        self.botname = botname

    def _command(self, command):

        # Run the command in the srvx object
        parts = command.split(' ', 2)
        if len(parts) > 1:
            return self.srvx.send_command('opserv helpserv %s %s %s' % (parts[0], self.botname, parts[1]))
        elif len(parts) > 0:
            return self.srvx.send_command('opserv helpserv %s %s' % (parts[0], self.botname))

    def stats(self, account):

        # Get the stats of the user
        response = self._command('stats *%s' % account)

        if response['data'][0].endswith('has not been registered.'):
            return None, response['data'][0]

        if response['data'][0].find('lacks access to') != -1:
            return None, response['data'][0]

        if not response['data'][0].find('user %s (week starts' % account):
            return None, response['data'][0]

        data = {}

        # Weekstart
        c1 = response['data'][0].find('week starts') + 12
        c2 = response['data'][0].find(')',c1)
        data['weekstart'] = response['data'][0][c1:c2]

        # Time
        for i, key in {3: 'current', 4: 'last-1', 5: 'last-2', 6: 'last-3', 7: 'total'}.items():
            parts = response['data'][i].split()
            data[key] = {}
            data[key]['time'] = ' '.join(parts[-4:-1]).strip() + ' ' + parts[-1]

        # Requests
        for i, key in {10: 'requests_picked_up', 11: 'requests_closed', 12: 'reassigned_from', 13: 'reassigned_to'}.items():
            parts = response['data'][i].split()
            data['current'][key] = parts[-3].strip()
            data['last-1'][key] = parts[-2].strip()
            data['total'][key] = parts[-1].strip()

        return data, None
