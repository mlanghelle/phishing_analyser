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

from email_provider import GLOBAL_MAIL
from email_provider import get_messages, delete_message
from email import policy
from email.parser import BytesParser

# returns index of first instance found in text
def findNext(instance, text):
    for index in range(len(text)):
        if text[index] == instance:
            return index

def curl(link):
    # TODO: not implementet (obviously)
    return True

def getPhisher(email_object):
    GLOBAL_PHISHER = None
    whitelist = [GLOBAL_MAIL, email_object["user"]]
    allowed_chars = "abcdefghijklmnopqrstuvwxyzæøå0123456789._%+-"
    found_emails = []
    body = email_object["body"].lower()

    if "from: " in body or "fra: " in body:
        start = findNext('<', body)
        end = findNext('>', body[start+1:-1]) + start
        GLOBAL_PHISHER = body[start+1:end+1]

    for i in range(len(body)):
        if body[i] == "@":
            start = i-1
            try:
                while body[start] in allowed_chars:
                    start -= 1
            except IndexError:
                continue
            start +=1
            end = i+1
            try:
                while body[end] in allowed_chars:
                    end += 1
            except IndexError:
                continue
            email = body[start:end]
            if "." in email.split("@")[1] and " " not in email and email not in whitelist and email not in found_emails:
<<<<<<< Updated upstream
                found_emails.append(email)
    return found_emails
=======
                found_emails.append(email) # email contains "." after "@"
    if GLOBAL_PHISHER:
        return GLOBAL_PHISHER, found_emails
    return False, found_emails
>>>>>>> Stashed changes

def findWebLinks(email_object):
    # Save links as key, formatted html "link" as value
    # If value is different then key = suspicious; -> attacker is attempting to trick user
    web_links = dict()
    raw = email_object["raw_body"].get_content().split("href")
    for split in raw:
        start = findNext('"', split)
        end = findNext('"', split[start+1:-1])
        current_link = split[start+1:start+end+1]
        if "." in current_link:
            if "mailto:" in current_link:
                mail = current_link.split("mailto:")[1]
                if mail == email_object["user"] or mail == email_object["phisher"]:
                    continue
            if curl(current_link):
                anchor_start = findNext('>', split[end+1:-1])
                anchor_end = findNext('<', split[end+anchor_start+1:-1])
                current_anchor = split[end+1 + anchor_start+1:end + anchor_start+anchor_end+1]
                if "\r" in current_anchor or "\n" in current_anchor:
                    current_anchor = current_anchor.replace("\r", "")
                    current_anchor = current_anchor.replace("\n", "")
                web_links[current_link] = current_anchor
    if len(web_links) > 0:
        return web_links
    return None
    
def getDomains(link_dict):
    #TODO: implement, need a short summary of domains of the web_links
    domains = set()
    list = []
    if link_dict:
        for url in link_dict.keys():
            for i in range(len(url)):
                if url[i] == "/":
                    try:
                        if url[i+1] == "/" or url[i-1] == "/":
                            continue
                    except IndexError:
                        pass
                    domains.add(url[0:i])
                    break
    return domains

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
        "attachments": None,
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

    attachments = []
    for attachment in outer_msg.iter_attachments():
        current_attachment = dict()
        current_attachment["filename"] = attachment.get_filename()
        current_attachment["content_type"] = attachment.get_content_type()
        current_attachment["content"] = attachment.get_payload(decode=True)
        attachments.append(current_attachment)

    if len(attachments) > 0:
        email_object["attachments"] = attachments

    GLOBAL_PHISHER, email_object["phish_list"] = getPhisher(email_object)
    if GLOBAL_PHISHER:
        email_object["global_phisher"] = GLOBAL_PHISHER
    email_object["urls"] = findWebLinks(email_object)
    if email_object["urls"]:
        email_object["domains"] = getDomains(email_object["urls"])

    # look for reply-to

    return email_object

messages = get_messages()
for email in messages:
    object = parse(email)

    report = None
    if object["forwarded"]:
        print(object["domains"])
        # do something with sender(s) regardless, domain reputation (?)

        #if object["attachments"]:
            #do something

        #if object["web-links"]:
            #do something

        # analyze language

        # analyze wording ("click here" etc)

        # report = generate_report(object)
    
    # send_email(object["user"], report) (send_email(None) -> (Missing inner body or "Fwd: " in subject line))
    # delete_message(email["id"])