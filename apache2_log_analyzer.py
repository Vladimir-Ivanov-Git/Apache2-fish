#!/usr/bin/env python

from argparse import ArgumentParser
from apache2_setup_proxy import Base
from time import sleep
from re import match
import os
import urllib


def search_credentials(data):
    parameter_name_for_user = [
        "username",
        "email",
        "login",
        "loginbox",
        "field(login)",
        "session[username_or_email]",
        "identifier",
        "accountName"
    ]

    parameter_name_for_password = [
        "password",
        "passwordbox",
        "pass",
        "passwd",
        "field(password)",
        "session[password]"
    ]

    user = None
    password = None
    user_parameter = None
    password_parameter = None

    data = urllib.unquote(data).decode('utf8')

    for parameters in data.split("&"):
        try:
            parameter_name = parameters.split("=")[0]
            parameter_value = parameters.split("=")[1]

            for parameter in parameter_name_for_user:
                if parameter_name.lower() == parameter:
                    user_parameter = parameter_name
                    user = parameter_value

            for parameter in parameter_name_for_password:
                if parameter_name.lower() == parameter:
                    password_parameter = parameter_name
                    password = parameter_value

        except IndexError:
            pass

    if user is not None and password is not None:
        return {
            "user_parameter": user_parameter,
            "password_parameter": password_parameter,
            "user": user,
            "password": password
        }
    else:
        return None


if __name__ == "__main__":
    Base = Base()
    Base.check_platform()

    parser = ArgumentParser(description='Apache2 audit log analyzer')

    parser.add_argument('-u', '--url', type=str, help='Set URL (example: "http://test.com")', default=None)
    parser.add_argument('-l', '--log_dir', type=str, help='Set Apache2 log dir (default: "/var/log/apache2")',
                        default="/var/log/apache2")
    parser.add_argument('-t', '--refresh_time', type=int, help='Set read log refresh time (default: "5")',
                        default=5)
    parser.add_argument('-c', '--creds', action='store_true', help='Show credentials only')

    args = parser.parse_args()

    log_files = []

    if args.url is None:
        for log_file in os.listdir(args.log_dir):
            if log_file.endswith("-audit.log"):
                re = match(r"^(?P<proto>http|https)\-(?P<host>[A-Za-z0-9\-\.]+)\-audit\.log$", log_file)
                log_files.append({
                    "path": args.log_dir + "/" + log_file,
                    "proto": re.group('proto'),
                    "host": re.group('host'),
                    "descriptor": open(args.log_dir + "/" + log_file, 'r')
                })
    else:
        log_file = args.log_dir + "/" + args.url.split('://')[0] + "-" + args.url.split('://')[1] + "-audit.log"
        if Base.check_file_exist(log_file):
            log_files.append({
                "path": log_file,
                "proto": args.url.split('://')[0],
                "host": args.url.split('://')[1],
                "descriptor": open(log_file, 'r')
            })
        else:
            print Base.c_error + "File: " + log_file + " not found!"
            exit(1)

    if len(log_files) == 0:
        print Base.c_error + "Apache2 audit log files not found!"
        exit(1)

    while True:
        for log_file in log_files:
            requests = []
            log_file_lines = log_file["descriptor"].readlines()
            if len(log_file_lines) > 0:
                for index in range(len(log_file_lines)):
                    re = match(r"^\-\-(?P<request_id>[a-z0-9]+)\-A\-\-$", log_file_lines[index])
                    if re is not None:
                        requests.append(index)

            if len(requests) > 0:
                for request_index in range(len(requests)):
                    start_position = requests[request_index]
                    try:
                        stop_position = requests[request_index + 1] - 1
                    except IndexError:
                        stop_position = len(log_file_lines)
                    # print "Start: " + str(start_position)
                    # print "Stop: " + str(stop_position)

                    re = match(r"^\-\-(?P<request_id>[a-z0-9]+)\-A\-\-$", log_file_lines[start_position])
                    request_id = re.group('request_id')
                    request_path = log_file_lines[start_position + 3].split(' ')[1]
                    request_data = ""
                    request_method = log_file_lines[start_position + 3].split(' ')[0]
                    request_user_agent = ""
                    request_cookie = ""
                    response_status = ""
                    client = log_file_lines[start_position+1].split(' ')[3]
                    server = log_file["host"]
                    proto = log_file["proto"]

                    if not args.creds:
                        if match(r"^(.(?!\.(jpg|jpeg|png|css|gif|ico|js)))*$")
                            print Base.c_success + "[Request ID] " + request_id
                            print Base.c_info + "[Client] " + client
                            print Base.c_info + "[Client port] " + log_file_lines[start_position+1].split(' ')[4]
                            print Base.c_info + "[Server] " + server
                            print Base.c_info + "[Proto] " + proto
                            print Base.c_info + "[Request method] " + request_method
                            print Base.c_info + "[Request path] " + request_path

                            for index in range(start_position, stop_position, 1):
                                re = match(r"^User\-Agent\:(| )(?P<user_agent>.*)$", log_file_lines[index])
                                if re is not None:
                                    request_user_agent = re.group('user_agent')

                                re = match(r"^Cookie\:(| )(?P<cookie>.*)$", log_file_lines[index])
                                if re is not None:
                                    request_cookie = re.group('cookie')

                                re = match(r"^\-\-" + request_id + "\-C\-\-$", log_file_lines[index])
                                if re is not None:
                                    request_data = log_file_lines[index + 1].replace('\n', '')

                                re = match(r"^\-\-" + request_id + "\-F\-\-$", log_file_lines[index])
                                if re is not None:
                                    response_status = log_file_lines[index + 1].replace('\n', '')[9:]

                            if not args.creds:
                                print Base.c_info + "[User-Agent] " + request_user_agent
                                if request_cookie != "":
                                    print Base.c_success + "[Cookie] " + Base.cSUCCESS + request_cookie + Base.cEND
                                if request_data != "":
                                    print Base.c_success + "[Request data] " + Base.cSUCCESS + request_data + Base.cEND
                                print Base.c_info + "[Response Status] " + response_status + "\n"

                    analyze_data = [request_path, request_data]

                    for data in analyze_data:
                        creds = search_credentials(data)
                        if creds is not None:
                            print "\n" + Base.cSUCCESS + "[Credentials found]" + Base.cEND
                            print Base.cINFO + "[Client] " + Base.cEND + client
                            print Base.cINFO + "[Server] " + Base.cEND + server
                            print Base.cINFO + "[Path] " + Base.cEND + request_path
                            print Base.cINFO + "[Request Method] " + Base.cEND + request_method
                            print Base.cINFO + "[Response Status] " + Base.cEND + response_status
                            print Base.cINFO + "[" + creds["user_parameter"] + "] " + \
                                  Base.cSUCCESS + creds["user"] + Base.cEND
                            print Base.cINFO + "[" + creds["password_parameter"] + "] " + \
                                  Base.cSUCCESS + creds["password"] + Base.cEND + "\n"

                            credentials_file_name = proto + "-" + server + "-credentials.log"
                            new_credentials = creds["user"] + " " + creds["password"] + "\n"

                            if Base.check_file_exist(credentials_file_name):
                                with open(credentials_file_name, 'r') as credentials_file:
                                    credentials = credentials_file.readlines()
                                    if new_credentials not in credentials:
                                        credentials_file.close()
                                        with open(credentials_file_name, 'a') as credentials_file_append:
                                            credentials_file_append.write(new_credentials)
                            else:
                                with open(credentials_file_name, 'a') as credentials_file:
                                    credentials_file.write(new_credentials)

        sleep(args.refresh_time)
