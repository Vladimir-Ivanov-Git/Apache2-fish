#!/usr/bin/env python

from argparse import ArgumentParser
from platform import system, release
from sys import exit
from pwd import getpwuid
import os


class Base:
    cINFO = None
    cERROR = None
    cSUCCESS = None
    cWARNING = None
    cEND = None

    c_info = None
    c_error = None
    c_success = None
    c_warning = None

    def __init__(self):
        self.cINFO = '\033[1;34m'
        self.cERROR = '\033[1;31m'
        self.cSUCCESS = '\033[1;32m'
        self.cWARNING = '\033[1;33m'
        self.cEND = '\033[0m'

        self.c_info = self.cINFO + '[*]' + self.cEND + ' '
        self.c_error = self.cERROR + '[-]' + self.cEND + ' '
        self.c_success = self.cSUCCESS + '[+]' + self.cEND + ' '
        self.c_warning = self.cWARNING + '[!]' + self.cEND + ' '

    @staticmethod
    def check_platform():
        if system() != "Linux":
            print "This script can run only in Linux platform!"
            print "Your platform: " + str(system()) + " " + str(release()) + " not supported!"
            exit(1)

    @staticmethod
    def check_user():
        if os.getuid() != 0:
            print "Only root can run this script!"
            print "You: " + str(getpwuid(os.getuid())[0]) + " can not run this script!"
            exit(1)

    @staticmethod
    def check_file_exist(file_name):
        return os.path.isfile(file_name)


if __name__ == "__main__":
    Base = Base()
    Base.check_user()
    Base.check_platform()

    parser = ArgumentParser(description='Setup Apache2 proxy')
    parser.add_argument('-u', '--url', type=str, help='Set URL for proxy', default='http://test.com')
    parser.add_argument('-C', '--country', type=str, help='Set Country for SSL cert (default: RU)',
                        default='RU')
    parser.add_argument('-S', '--state', type=str, help='Set State for SSL cert (default: Moscow)',
                        default='Moscow')
    parser.add_argument('-L', '--locality', type=str, help='Set Locality for SSL cert (default: Moscow)',
                        default='Moscow')
    parser.add_argument('-O', '--organization', type=str, help='Set Organization for SSL cert')
    parser.add_argument('-U', '--organization_unit', type=str, help='Set Organization unit for SSL cert (default: IT)',
                        default='IT')
    parser.add_argument('-c', '--http_config', type=str,
                        help='Set path to Apache2 http site config '
                             '(default: /etc/apache2/sites-available/000-default.conf)',
                        default='/etc/apache2/sites-available/000-default.conf')
    parser.add_argument('-s', '--https_config', type=str,
                        help='Set path to Apache2 https site config '
                             '(default: /etc/apache2/sites-available/default-ssl.conf)',
                        default='/etc/apache2/sites-available/default-ssl.conf')
    args = parser.parse_args()

    schema = "http"
    domain = "test.com"

    try:
        schema = args.url.split("://")[0]
        domain = args.url.split("://")[1]
    except IndexError:
        print Base.c_error + "Bad url: " + args.url
        print Base.c_info + "Normal url: http://test.com"
        exit(1)

    if schema == "http" or schema == "https":
        print Base.c_info + "Schema: " + schema
        print Base.c_info + "Domain: " + domain
    else:
        print Base.c_error + "Bad schema: " + str(schema)
        print Base.c_info + "Normal schema: http or https"
        exit(1)

    if args.organization is None:
        args.organization = domain

    if schema == "http":
        with open(args.http_config, "a") as http_config_file:
            http_config_file.write("\n\n<VirtualHost *:80>" +
                                   "\n\tServerName " + domain +
                                   "\n\tServerAdmin admin@" + domain +
                                   "\n\tProxyPass \"/\" \"" + args.url + "/\"" +
                                   "\n\tProxyPassReverse \"/\" \"" + args.url + "/\"" +
                                   "\n\tSecRuleEngine On" +
                                   "\n\tSecAuditEngine on" +
                                   "\n\tSecAuditLog ${APACHE_LOG_DIR}/http." + domain + "-audit.log" +
                                   "\n\tErrorLog ${APACHE_LOG_DIR}/http." + domain + "-error.log" +
                                   "\n\tCustomLog ${APACHE_LOG_DIR}/http." + domain + "-access.log combined" +
                                   "\n\tSecRequestBodyAccess on" +
                                   "\n\tSecAuditLogParts ABIFHZ" +
                                   "\n\tSecDefaultAction \"nolog,noauditlog,allow,phase:2\"" +
                                   "\n\tSecRule REQUEST_METHOD \"^POST$\" \"chain,allow,phase:2,id:123\"" +
                                   "\n\tSecRule REQUEST_URI \".*\" \"auditlog\"" +
                                   "\n</VirtualHost>")

    if schema == "https":
        print Base.c_info + "Create SSL cert and key"
        os.system("openssl req -nodes -new -x509 -days 365 -keyout " + domain + ".key -out " + domain + ".pem " +
                  "-subj '/C=" + args.country + "/ST=" + args.state + "/L=" + args.locality +
                  "/O=" + args.organization + "/OU=" + args.organization_unit + "/CN=" + domain + "'")
        os.system("mv " + domain + ".pem /etc/ssl/certs/")
        os.system("mv " + domain + ".key /etc/ssl/private/")
        os.system("chmod 0600 /etc/ssl/private/" + domain + ".key")
        os.system("openssl x509 -in /etc/ssl/certs/" + domain + ".pem -noout -text")

        if Base.check_file_exist("/etc/ssl/certs/" + domain + ".pem") and Base.check_file_exist("/etc/ssl/private/" + domain + ".key"):
            print Base.c_info + "SSL cert: /etc/ssl/certs/" + domain + ".pem"
            print Base.c_info + "SSL key: /etc/ssl/private/" + domain + ".key"
        else:
            print Base.c_error + "Can not create SSL cert and key"
            exit(1)

        with open(args.http_config, "a") as http_config_file:
            http_config_file.write("\n\n<VirtualHost *:80>" +
                                   "\n\tServerName " + domain +
                                   "\n\tServerAdmin admin@" + domain +
                                   "\n\tProxyPass \"/\" \"" + args.url + "/\"" +
                                   "\n\tProxyPassReverse \"/\" \"" + args.url + "/\"" +
                                   "\n\tSecRuleEngine On" +
                                   "\n\tSecAuditEngine on" +
                                   "\n\tSecAuditLog ${APACHE_LOG_DIR}/http." + domain + "-audit.log" +
                                   "\n\tErrorLog ${APACHE_LOG_DIR}/http." + domain + "-error.log" +
                                   "\n\tCustomLog ${APACHE_LOG_DIR}/http." + domain + "-access.log combined" +
                                   "\n\tSecRequestBodyAccess on" +
                                   "\n\tSecAuditLogParts ABIFHZ" +
                                   "\n\tSecDefaultAction \"nolog,noauditlog,allow,phase:2\"" +
                                   "\n\tSecRule REQUEST_METHOD \"^POST$\" \"chain,allow,phase:2,id:123\"" +
                                   "\n\tSecRule REQUEST_URI \".*\" \"auditlog\"" +
                                   "\n\tSSLProxyEngine On" +
                                   "\n</VirtualHost>")

        with open(args.https_config, "a") as https_config_file:
            https_config_file.write("\n\n<IfModule mod_ssl.c>" +
                                    "\n\t<VirtualHost _default_:443>" +
                                    "\n\t\tServerName " + domain +
                                    "\n\t\tServerAdmin admin@" + domain +
                                    "\n\t\tProxyPass \"/\" \"" + args.url + "/\"" +
                                    "\n\t\tProxyPassReverse \"/\" \"" + args.url + "/\"" +
                                    "\n\t\tSecRuleEngine On" +
                                    "\n\t\tSecAuditEngine on" +
                                    "\n\t\tSecAuditLog ${APACHE_LOG_DIR}/https." + domain + "-audit.log" +
                                    "\n\t\tErrorLog ${APACHE_LOG_DIR}/https." + domain + "-error.log" +
                                    "\n\t\tCustomLog ${APACHE_LOG_DIR}/https." + domain + "-access.log combined" +
                                    "\n\t\tSecRequestBodyAccess on" +
                                    "\n\t\tSecAuditLogParts ABIFHZ" +
                                    "\n\t\tSecDefaultAction \"nolog,noauditlog,allow,phase:2\"" +
                                    "\n\t\tSecRule REQUEST_METHOD \"^POST$\" \"chain,allow,phase:2,id:123\"" +
                                    "\n\t\tSecRule REQUEST_URI \".*\" \"auditlog\"" +
                                    "\n\t\tSSLEngine on" +
                                    "\n\t\tSSLProxyEngine On" +
                                    "\n\t\tSSLCertificateFile /etc/ssl/certs/" + domain + ".pem" +
                                    "\n\t\tSSLCertificateKeyFile /etc/ssl/private/" + domain + ".key" +
                                    "\n\t</VirtualHost>" +
                                    "\n</IfModule>")

    print Base.c_info + "Restart Apache2 server"
    os.system("/etc/init.d/apache2 restart")
