"""
Main application.

This file handles the general email analysis and should remain
independent of the email provider being used.

The email provider is responsible for retrieving messages and returning
them as raw email data. This file then parses and processes those
messages for analysis.

Provider-specific code should not be added here.

Author: Magnus Langhelle
"""

from email_provider import get_messages, delete_message
from email import policy
from email.parser import BytesParser

# Parse to EmailMessage object
def parse(outer):
    outer_msg = BytesParser(policy=policy.default).parsebytes(outer["raw"])

    # Dont analyse non-forwarded emails
    if "Fwd: " not in outer_msg["subject"] and "Vs: " not in outer_msg["subject"]:
        return None

    inner = outer_msg.get_body(preferencelist=("plain", "html"))
    inner_msg = inner.get_content()

    if not inner_msg:
        return None

    email_object = {
        "id": outer["id"],
        "body": inner_msg,
        "user": outer_msg["Return-Path"][0:-1],
        "phisher": None,
        "reply-to": None,
        "subject": outer_msg["Subject"],
        "attachments": [],
        "web-links":[],
    }

    for attachment in outer_msg.iter_attachments():
        current_attachment = dict()
        current_attachment["filename"] = attachment.get_filename()
        current_attachment["content_type"] = attachment.get_content_type()
        current_attachment["content"] = attachment.get_payload(decode=True)

    return email_object

messages = get_messages()

for email in messages:
    object = parse(email)

    if not object:
        print("Message skipped")
        # Send instructions to sender ("Fwd: " must be in subject)
        #delete_message(email["id"])
        continue

    #if object["attachements"][0]:
        #do something

    #if object["links"][0]:
        #do something

    #delete_message(email["id"])