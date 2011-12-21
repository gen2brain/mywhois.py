#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Milan Nikolic <gen2brain@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import sys
from commands import getoutput
from optparse import OptionParser
from Queue import Queue
from threading import Thread

SOCKS_PORT = 9050
SOCKS_SERVER = '127.0.0.1'

REGISTRAR_RE = [
    re.compile('registrant\s*:\s*(.+)'),
    re.compile('Registrar:\s*\n\s*Name:\s*(.+)'),
    re.compile('Registrant:\s*\n\s*Name:\s*(.+)'),
    re.compile('Registrant\s*\n(.+)\nName:\s*(.+)'),
    re.compile('Registrar Name:\s+(.+)'),
    re.compile('Registrar\s+:\s+(.+)'),
    re.compile('Sponsoring Registrar:\s*(.+)'),
    re.compile('Registrar:\s*\n\s*(.+)'),
    re.compile('Registrar:\s*(.+)'),
    re.compile('registrar:\s+(.+)'),
    re.compile('registrar:\s*(.+)'),
    re.compile('organization:\s*(.+)'),
    re.compile('registrant:\s*(.+)'),
    re.compile('REGISTRAR:\s*\n(.+)'),
    re.compile('Registrar\s*\n\s*Organization:\s*(.+)'),
    re.compile('Type:\s*ROLE|PERSON\s*\nName:\s*(.+)'),
    re.compile('owner:\s*(.+)'),
    re.compile('Holder of domain name:\s*\n(.+)'),
    re.compile('Admin-name\s*(.+)'),
    re.compile('\[Registrar\]\n.*\nName:\s*(.+)'),
    re.compile('Representing\s*(.+)'),
    re.compile('Titular:\s*\r\n.*\r\n\s*(.+)')
    ]

NAMESERVER_RE = [
    re.compile('Hostname:\s*(.+)'),
    re.compile('Name Server:\s*([a-zA-Z0-9\.-]+)'),
    re.compile('Nameservers\s*\n(.+)\s*(.+)'),
    re.compile('Nameservers:\s*\n\s*(.+)\n\s*(.+)'),
    re.compile('Name servers:\s*\n\s*(.+)\n\s*(.+)'),
    re.compile('Nameservers:(.+)'),
    re.compile('Nameserver:\s*(.+)'),
    re.compile('Nserver:\s+(.+)'),
    re.compile('nserver:\s*(.+)'),
    re.compile('fqdn\s*:\s(.+)\n'),
    re.compile('DNS:\s*(.+)\s*-'),
    re.compile('DNS:\s*(.+)'),
    re.compile('dns_name\s*(.+)'),
    re.compile('Nombres de Dominio:\r\n\r\n\s*-\s(.+)\r\n\s*-\s(.+)'),
    re.compile('nameservers:\s*(.+)\n\s*(.+)'),
    re.compile('Domain nameservers:\s*\n\s*(.+)\s*\n\s*(.+)'),
    re.compile('\(Domain servers\):\s*\n\s*(.+)\s*\n\s*(.+)'),
    re.compile('\s{8}([a-zA-Z0-9\.-]+)\s+[\d\.]+')
    ]

class Whois():
    """Lookup and parse WHOIS information"""

    def __init__(self, domainname):
        """Constructor"""
        if domainname.endswith('.'):
            self.domainname = domainname[:-1]
        else:
            self.domainname = domainname
        self.domainext = self.domainname.rsplit('.')[-1]

        if self.domainext in ['de']:
            self.query = '-T dn %s' % self.domainname
        else:
            self.query = self.domainname

        self.url = None
        self.error = None
        self.server = self.get_server()
        self.method = self.get_method()

    def get_server(self):
        """Returns whois server"""
        server = None
        if self.domainext:
            output = getoutput("dig %s.whois-servers.net any +short +tcp" % (
                self.domainext))
        if output:
            server = output.split("\n")[0]
        return server

    def get_method(self):
        method = None
        if not self.server:
            if self.domainext == 'za':
                method = 'http'
                self.url = 'http://www.coza.net.za/cgi-bin/whois.sh?Domain=%s' % (
                        self.domainname)
            elif self.domainext == 've':
                method = 'socket'
                self.server = 'whois.nic.ve'
            elif self.domainext == 'ph':
                self.error = "for 'ph' domains go to http://www.dot.ph/whois"
            else:
                self.error = "whois server not found for '%s' domain." % (
                        self.domainext)
        else:
            if self.domainext == 'es':
                self.error = "for 'es' domains go to https://www.nic.es"
            elif self.domainext == 'hu':
                self.error = "for 'hu' domains go to http://www.domain.hu/domain/English/domainsearch"
            else:
                method = 'socket'
        return method

class Worker(Thread):
    """ Threadable class allowing parallel sessions """

    def __init__(self, whois, opts):
        Thread.__init__(self)
        self.opts = opts
        self.domainname = whois.domainname
        self.server = whois.server
        self.method = whois.method
        self.query = whois.query
        self.url = whois.url
        self.error = whois.error

    def get_http_response(self):
        """Returns data from web whois"""
        response = ''
        try:
            user_agent = 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)'
            req = urllib2.Request(self.url, headers={'User-Agent': user_agent})
            url = urllib2.urlopen(req)
            while True:
                data = url.read(1024)
                if not data: break
                response += data
            url.close()
        except Exception, err:
            self.error = "%s: %s" % (self.url, str(err))
        return re.sub('<[^<]+?>', '', response)

    def get_socket_response(self):
        """Returns data from whois server"""
        response = ''
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server, 43))
            sock.send("%s\r\n" % self.query)
            while True:
                data = sock.recv(1024)
                if not data: break
                response += data
            sock.close()
        except Exception, err:
            self.error = "%s: %s" % (self.server, str(err))
        return response

    def parse_response(self, response):
        """Parses raw whois data"""
        registrar, nameservers = [], []
        for parse in [(registrar, REGISTRAR_RE),
                    (nameservers, NAMESERVER_RE)]:
            store, regex_list = parse
            for regex in regex_list:
                findall = regex.findall(response)
                if findall:
                    for match in findall:
                        if match:
                            if isinstance(match, tuple):
                                for m in match:
                                    store.append(m.strip())
                            else:
                                store.append(match.strip())
                    break
            store = [st for st in store if st and st not in store]
        return registrar, nameservers

    def run(self):
        results = None
        if self.error:
            results = "Error: %s\n" % self.error
            response = None
        elif self.method == "http":
            response = self.get_http_response()
        elif self.method == "socket":
            response = self.get_socket_response()

        if response:
            if self.opts.raw:
                results = "\n%s" % response
            else:
                registrar, nameservers = self.parse_response(response)
                results = "Registrar: %s\nNameservers: %s\n" % (
                        ", ".join(registrar), ", ".join(nameservers))
        else:
            if self.error:
                results = "Error: %s\n" % self.error
        sys.stdout.write("%s\n%s\n" % (self.domainname, results))


def parse_args():
    usage = "Usage: %prog <options> <args>\n"
    parser = OptionParser(usage=usage)
    parser.add_option('--raw', action='store_true', dest='raw', default=False,
            help='print raw whois response')
    parser.add_option('--tor', action='store_true', dest='tor',
            help='use tor (the onion router) proxy')
    parser.add_option('--tor-server', action='store', dest='tor_server', type='string',
            help='tor server ip address.')
    parser.add_option('--tor-port', action='store', dest='tor_port', type='string',
            help='tor server port number.')
    opts, args = parser.parse_args()

    if not args and sys.stdin.isatty():
        parser.print_help()
        sys.exit(1)

    if not sys.stdin.isatty():
        args = []
        for arg in sys.stdin.readlines():
            args.append(arg.strip())

    for arg in args:
        if os.path.isfile(arg) and os.access(arg, os.R_OK):
            args.remove(arg)
            fd = open(arg, 'r')
            for line in fd.readlines():
                args.append(line.strip())
            fd.close()

    return opts, args

def main(opts, args):

    def producer(queue, args):
        for arg in args:
            whois = Whois(arg)
            thread = Worker(whois, opts)
            thread.start()
            queue.put(thread, True)

    def consumer(queue, total):
        finished = 0
        while finished < total:
            thread = queue.get(True)
            thread.join()
            finished += 1

    queue = Queue(5)
    prod_thread = Thread(target=producer, args=(queue, args))
    cons_thread = Thread(target=consumer, args=(queue, len(args)))
    prod_thread.start()
    cons_thread.start()
    prod_thread.join()
    cons_thread.join()


if __name__ == '__main__':
    opts, args = parse_args()
    if opts.tor:
        import socks
        import socket
        server = (SOCKS_SERVER, opts.tor_server)[bool(opts.tor_server)]
        port = (SOCKS_PORT, opts.tor_port)[bool(opts.tor_port)]
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, server, port)
        socket.socket = socks.socksocket
        import urllib2
    else:
        import socket
        import urllib2

    try:
        main(opts, args)
    except KeyboardInterrupt:
        pass
