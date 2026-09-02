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

    email_object = {
        "forwarded": False,
        "id": outer["id"],
        "user": outer_msg["Return-Path"][0:-1],
        "body": None,
        "phisher": None,
        "reply-to": None,
        "subject": outer_msg["Subject"],
        "attachments": [],
        "web-links":[],
    }

    # Dont analyse non-forwarded emails
    if "Fwd: " not in outer_msg["subject"] and "Vs: " not in outer_msg["subject"]:
        return email_object

    inner = outer_msg.get_body(preferencelist=("plain", "html"))
    inner_msg = inner.get_content()

    if not inner_msg:
        return email_object

    email_object["forwarded"] = True
    email_object["body"] = inner_msg

    for attachment in outer_msg.iter_attachments():
        current_attachment = dict()
        current_attachment["filename"] = attachment.get_filename()
        current_attachment["content_type"] = attachment.get_content_type()
        current_attachment["content"] = attachment.get_payload(decode=True)


    # add all links to web_links

    # add phisher

    # add reply-to
        
    return email_object

messages = get_messages()

for email in messages:
    object = parse(email)

    if not object["Forwarded"]:
        print("Message skipped")
        # Send instructions to sender ("Fwd: " must be in subject)
        # report = generate_report(None)
        # send_email()
        # delete_message(email["id"])
        continue

    #if object["attachments"][0]:
        #do something

    #if object["web-links"][0]:
        #do something

    # report = generate_report(object)
    # send_email(object["user"], report)

    #delete_message(email["id"])