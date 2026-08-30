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

# TODO: Phishing email header and body will be located in the body of the outer email, and must be extracted accordingly.
# TODO: Similar emails forwarded using different services might be handled differently.

from email_provider import get_messages, delete_message
from email import policy
from email.parser import BytesParser

# Parse to EmailMessage object, then dictrionary
def parse(outer):
    outer_msg = BytesParser(policy=policy.default).parsebytes(outer["raw"])

    # Dont analyse non-forwarded emails
    if "Fwd: " not in outer_msg["subject"] and "Vs: " not in outer_msg["subject"]:
        return None

    inner = outer_msg.get_body(preferencelist=("plain", "html"))
    inner_msg = inner.get_content()

    if not inner_msg:
        return None

    """
    message_data = {
        "from": msg["From"],
        "to": msg["To"],
        "cc": msg["Cc"],
        "subject": msg["Subject"],
        "message_id": msg["Message-ID"],
        "headers": dict(msg.items()),
        "body": None,
        "attachments": []
    }

    for attachment in msg.iter_attachments():
        current_attachement = dict()
        current_attachement["filename"] = attachment.get_filename()
        current_attachement["content_type"] = attachment.get_content_type()
        current_attachement["content"] = attachment.get_payload(decode=True)

        message_data["attachments"].append(current_attachement)
    """

    return inner_msg, inner

messages = get_messages()
print(f"Found {len(messages)} messages.")

for email in messages:
    body, full = parse(email)

    if not body:
        print("Message skipped")
        # Send instructions to sender ("Fwd: " must be in subject)
        delete_message(email["id"])
        continue

    #delete_message(email["id"])