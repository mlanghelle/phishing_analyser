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
# Return single email if only one found, except for user.
# Return list if multiple, index 0 is likely to be phisher.
def getPhisher(email_object):
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
    found_emails = []
    at_indexes = []
    body = email_object["body"]

    # Given addresses are presented as <email>
    for i in range(len(body)):
        if body[i] == "<":
            for j in range(i, len(body)):
                if body[j] == ">":
                    pos_email = body[i+1:j]
                    if "@" in pos_email and "." in pos_email:
                        found_emails.append(pos_email)
                    break
        elif body[i] == "@":
            at_indexes.append(i)

    for index in at_indexes:
        pos_start = None
        pos_end = None
        pos_email = ""
        for i in range(index-1, -1, -1):
            if body[i] not in allowed_chars:
                pos_start = i+1
                break
        for i in range(index+1, len(body)):
            if body[i] not in allowed_chars:
                pos_end = i
                break

        if pos_start is not None and pos_end is not None:
            pos_email = body[pos_start:pos_end]
            if "@" in pos_email and "." in pos_email:
                if pos_email not in found_emails:
                    found_emails.append(pos_email)

    found_emails.remove(email_object["user"])
    if len(found_emails) == 1:
        return found_emails[0]
    return found_emails

# returns index of first instance found in text
def findNext(instance, text):
    for index in range(len(text)):
        if text[index] == instance:
            return index

def curl(link):
    # not implementet (obviously)
    return True

def getWebLinks(email_object):
    # Save links as key, formatted html "link" as value
    # If value is different then key = suspicious; -> attacker is attempting to trick user
    web_links = []
    raw = email_object["raw_body"].get_content().split("href")
    for split in raw:
        start = findNext('"', split)
        end = findNext('"', split[start+1:-1])
        current_link = split[start+1:start+end+1]
        if "." in current_link:
            if curl(current_link):
                web_links.append(current_link)

    return web_links
            # start of link is next ' " '
            # end of link is second next ' " '
    
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
        "reply_to": None,
        "subject": outer_msg["Subject"],
        "attachments": [],
        "web_links":None,
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
        email_object["attachments"].append(current_attachment)

    email_object["phisher"] = getPhisher(email_object)
    email_object["web_links"] = getWebLinks(email_object)

    # look for reply-to

    return email_object

messages = get_messages()
for email in messages:
    object = parse(email)
    print(object["body"])
    print("-- Found links: " + f"{object["web_links"]}")
    print("-"*35 + "\n")

    # do something with sender(s) regardless

    #if object["attachments"][0]:
        #do something

    #if object["web-links"][0]:
        #do something

    # analyze language

    # analyze wording ("click here" etc)

    report = None
    #if object["forwarded"]:
        # report = generate_report(object)
    
    # send_email(object["user"], report) (send_email(None) -> (Missing inner body or "Fwd: " in subject line))
    # delete_message(email["id"])