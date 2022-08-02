# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation

import re


class message(object):
    def __init__(self):
        '''register our criteria for being passed a message
           as a list of lower case strings or values to match with an event's dictionary of keys or values
           set the priority if you have a preference for order of plugins to run.
           0 goes first, 100 is assumed/default if not sent
        '''
        self.registration = ['snmptt']
        self.priority = 5
        self.regex = re.compile(r'(?P<trapname>\S+) (?P<trapseverity>\S+) "Status Events" (?P<source_host>\S+) - (?P<trappayload>.*)')

    def onMessage(self, message, metadata):
        if (
            'details' in message
            and 'program' in message['details']
            and message['details']['program'] == 'snmptt'
        ):
            msg_unparsed = message['summary']
            if search := re.search(self.regex, msg_unparsed):
                message['details']['trapname'] = search['trapname']
                message['details']['trapseverity'] = search['trapseverity']
                message['details']['trappayload'] = search['trappayload']
                message['hostname'] = search['source_host']
                # tag the message
                if 'tags' in message and isinstance(message['tags'], list):
                    message['tags'].append('alert')
                else:
                    message['tags'] = ['alert']

        return (message, metadata)
