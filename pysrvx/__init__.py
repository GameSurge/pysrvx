"""
pysrvx Srvx QServer Integration Package
"""
from srvx import SrvX
from authserv import AuthServ
from chanserv import ChanServ
from helpserv import HelpServ, HelpServBot
from opserv import OpServ

__version__ = "0.2"

# If run via the command line
if __name__ == '__main__':
    import optparse
    import sys
    from pprint import pprint

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

    parser.add_option("-b", "--bind", action="store", dest="bind_ip",
                        default=None,
                        help="Local IP Address")

    parser.add_option("-p", "--port", action="store", dest="port",
                        default=7702,
                        help="Host TCP Port")

    parser.add_option("-k", "--password", action="store", dest="password",
                        help="QServer password")

    parser.add_option("-a", "--auth", action="store", dest="auth",
                        help="AuthServ username:password pair to use")

    parser.add_option("-H", "--helpserv", action="store", dest="helpbot",
                        default=None,
                        help="HelpServ bot name")

    # Parse our options and arguments
    options, args = parser.parse_args()

    # Make sure they passed in the password and auth string
    if not options.password or not options.auth:
        print 'Error: missing required parameters'
        parser.print_help()
        sys.exit(1)

    # Make sure the auth string is in foo:bar format
    auth = options.auth.split(':')
    if len(auth) < 2:
        print 'Error: invalid authserv credentials'
        parser.print_help()
        sys.exit(1)

    # Turn on debug logging
    logging.basicConfig(level=logging.INFO)

    if len(args) >= 2:

        # Intialize srvx
        srvx = SrvX(options.ipaddr, options.port, options.password,
            auth[0], auth[1], options.bind_ip)

        class_name = args[0].lower()
        function_name = args[1]

        if class_name == 'helpbot' and not options.helpbot:
            print 'Error: helpbot needs a helpserv bot nick'
            parser.print_help()
            sys.exit(1)

        if class_name == 'authserv':
            obj = AuthServ(srvx)
        elif class_name == 'chanserv':
            obj = ChanServ(srvx)
        elif class_name == 'helpserv':
            obj = HelpServ(srvx)
        elif class_name == 'helpbot':
            obj = HelpServBot(srvx, options.helpbot)
        elif class_name == 'opserv':
            obj = OpServ(srvx)

        # Get the function handle
        function = getattr(obj, function_name)

        logging.debug('Calling %s.%s' % (class_name, function_name))

        # Call the object function
        if len(args) == 2:
            pprint(function())
        elif len(args) == 3:
            pprint(function(args[2]))
        elif len(args) == 4:
            pprint(function(args[2], args[3]))
        elif len(args) == 5:
            pprint(function(args[2], args[3], args[4]))
        elif len(args) == 6:
            pprint(function(args[2], args[3], args[4], args[5]))
