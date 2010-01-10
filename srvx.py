#!/usr/bin/env python
"""
SrvX Module

Communicates with SrvX via QServer protocol
"""

__author__  = 'Gavin M. Roy <gavinmroy@gmail.com>'
__date__    = '2010-01-10'
__version__ = '0.1'

import logging

class SrvX:

    def __init__(self, host='127.0.0.1', port=8080):
        logging.debug('Connecting to %s:%i' % (host, port))
        
class AuthServ:

    def __init__(self):
        pass        

class ChanServ:

    def __init__(self):
        pass        

class OpServ:

    def __init__(self):
        pass        

if __name__ == 'main':
    
    # Command Line SrvX Usage
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
                        help="Host IP Address to connect to.")     

    parser.add_option("-p", "--port", action="store", dest="port", 
                        default=7702,
                        help="Host TCP Port to connect to.")     
                         
    # Parse our options and arguments                                                                        
    options, args = parser.parse_args()    
    
    srvx = SrvX(options.ipaddr, options.port)