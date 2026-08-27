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

# Parse to EmailMessage object, then dictrionary
def parse(message):
    msg = BytesParser(policy=policy.default).parsebytes(message["raw"])

    message_data = {
        "from": msg["From"],
        "to": msg["To"],
        "cc": msg["Cc"],
        "subject": msg["Subject"],
        "date": msg["Date"],
        "message_id": msg["Message-ID"],
        "headers": dict(msg.items()),
        "body": None,
        "attachments": []
    }

    body = msg.get_body(preferencelist=("plain", "html"))

    if body:
        message_data["body"] = body.get_content()

    for attachment in msg.iter_attachments():
        current_attachement = dict()
        current_attachement["filename"] = attachment.get_filename()
        current_attachement["content_type"] = attachment.get_content_type()
        current_attachement["content"] = attachment.get_payload(decode=True)

        message_data["attachments"].append(current_attachement)

    return message_data

messages = get_messages()
print(f"Found {len(messages)} messages.")

iterator = 0
for email in messages:
    iterator += 1
    print(f"- - - - - Message nr: {iterator} - - - - -")

    parsedMsg = parse(email)
    print(parsedMsg["attachments"])

    #delete_message(email["id"])
