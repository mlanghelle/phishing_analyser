"""
Main application.

This file handles the general email analysis workflow and should remain
independent of the email provider being used.

The email provider is responsible for retrieving messages and returning
them as raw email data. This file then parses and processes those
messages for further analysis.

Provider-specific code should not be added here.

Author: Magnus Langhelle
"""

from email_provider import get_messages, delete_message

messages = get_messages()

print(f"Found {len(messages)} messages.")

for message in messages:
    raw_email = message["raw"]
    print(raw_email.decode("utf-8", errors="replace"))

    #delete_message(message["id"])