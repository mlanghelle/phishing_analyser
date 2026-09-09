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

# TODO: Should save found web-links in dict - if key and value are different, is red flag.

# Look for possible phish-sender in the body. 
# First email listed, not identical to user, is likely to be phisher.
def getPhisher(email_object):
    found_emails = []
    angle_bracket_at_index = []
    at_indexes = []
    body = email_object["body"]

    # Given addresses are presented as <email>
    for i in range(len(body)):
        if body[i] == "<":
            for j in range(i, len(body)):
                if body[j] == ">":
                    found_emails.append(body[i+1:j])
                elif body[j] == "@":
                    angle_bracket_at_index.append(j)
        elif body[i] == "@":
            if i not in angle_bracket_at_index:
                at_indexes.append(i)

    # Investigate all possible emails found
    for index in at_indexes:
        pos_start = None
        pos_end = None
        pos_email = ""
        for i in range(index-1, 0, -1):
            if body[i] in " \r\n":
                pos_start = i+1
                break
        for i in range(index+1, len(body)):
            if body[i] in " \r\n":
                pos_end = i
                break

        if pos_start is not None and pos_end is not None:
            pos_email = body[pos_start:pos_end]
            if pos_email not in found_emails:
                found_emails.append(pos_email)

    #print(found_emails)
    print(found_emails)
    for email in found_emails:
        if "@" in email and "." in email:
            if email != email_object["user"]:
                return email

#def getWebLinks(email_object):

# Parse to EmailMessage object
def parse(outer):
    outer_msg = BytesParser(policy=policy.default).parsebytes(outer["raw"])

    email_object = {
        "forwarded": False,
        "id": outer["id"],
        "user": outer_msg["Return-Path"][1:-1],
        "body": None,
        "raw_body":None,
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
    email_object["raw_body"] = outer_msg.get_body()

    for attachment in outer_msg.iter_attachments():
        current_attachment = dict()
        current_attachment["filename"] = attachment.get_filename()
        current_attachment["content_type"] = attachment.get_content_type()
        current_attachment["content"] = attachment.get_payload(decode=True)

    email_object["phisher"] = getPhisher(email_object)

    #email_object["web-links"] = getWebLinks(email_object)

    # look for reply-to

    return email_object

messages = get_messages()
for email in messages:
    object = parse(email)

    #if object["attachments"][0]:
        #do something

    #if object["web-links"][0]:
        #do something

    report = None
    #if object["forwarded"]:
        # report = generate_report(object)
    
    # send_email(object["user"], report) (send_email(None) -> (Missing inner body or "Fwd: " in subject line))
    # delete_message(email["id"])