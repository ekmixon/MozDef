# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation

import urllib
from mozdef_util.utilities.toUTC import toUTC


class message(object):
    def __init__(self):
        """
            Plugin used to fix object type discretions with cloudtrail messages
        """
        self.registration = ["pubsub"]
        self.priority = 5

    def onMessage(self, message, metadata):
        # trust no one mr mulder
        if "tags" not in message:
            return (message, metadata)
        if "pubsub" not in message["tags"]:
            return (message, metadata)
        if "details" not in message:
            return (message, metadata)

        event = message["details"]

        if "logName" not in event:
            return (message, metadata)
            # XXX: implement filtering of audit types that we want to see (yaml)
        newmessage = {}
        logtype = "UNKNOWN"
        logtype = urllib.parse.unquote(event["logName"]).split("/")[-1].strip()
        if (
            "protoPayload" in event
            and "@type" in event["protoPayload"]
            and event["protoPayload"]["@type"]
            == "type.googleapis.com/google.cloud.audit.AuditLog"
            or "protoPayload" not in event
            and "jsonPayload" not in event
            and "textPayload" in event
            and "logName" in event
            and logtype == "syslog"
        ):
            newmessage["category"] = logtype
            newmessage["source"] = "stackdriver"
            newmessage["tags"] = message["tags"] + ["stackdriver"]
        elif (
            ("protoPayload" not in event or "@type" not in event["protoPayload"])
            and "protoPayload" not in event
            and (
                "jsonPayload" not in event
                or "logName" not in event
                or logtype == "activity_log"
            )
            and ("jsonPayload" not in event or "logName" in event)
            and (
                "jsonPayload" in event
                or "textPayload" not in event
                or "logName" not in event
            )
            and ("jsonPayload" in event or "textPayload" not in event)
            and "jsonPayload" in event
        ):
            newmessage["category"] = "gceactivity"
            newmessage["source"] = "stackdriver"
            newmessage["tags"] = message["tags"] + ["stackdriver"]
        newmessage["receivedtimestamp"] = toUTC(message["receivedtimestamp"]).isoformat()
        newmessage["timestamp"] = toUTC(event["timestamp"]).isoformat()
        newmessage["utctimestamp"] = toUTC(event["timestamp"]).isoformat()
        newmessage["mozdefhostname"] = message["mozdefhostname"]
        newmessage["customendpoint"] = ""
        newmessage["details"] = event

        return (newmessage, metadata)
