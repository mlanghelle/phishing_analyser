"""
Email provider interface.

This file is responsible for connecting to the user's chosen email
provider and retrieving incoming messages.

When setting up the project, configure this file to work with your
preferred email service (e.g. Gmail, Outlook, or another provider).

The get_messages() function returns a list of messages. Each message
contains a provider-specific ID and the decoded raw email.

If no messages are available, an empty list is returned.

The delete_message(id) function deletes a processed message from the
configured email inbox. This is done for privacy and security purposes,
and because retention settings have not yet been implemented.

Provider-specific authentication and API code should remain in this file
so that the rest of the application remains independent of the email
provider being used.

The current implementation uses the Google Gmail API. Users must provide
their own credentials.json and authenticate with their own Google account.
The resulting token.json is generated locally.
"""

import os.path
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://mail.google.com/"]


def get_service():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file(
            "token.json",
            SCOPES
        )

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def get_messages():
    service = get_service()

    results = service.users().messages().list(
        userId="me",
        maxResults=10
    ).execute()

    messages = results.get("messages", [])

    emails = []

    for message in messages:
        message_id = message["id"]

        full_message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw"
        ).execute()

        raw_email = full_message["raw"]
        decoded_email = base64.urlsafe_b64decode(raw_email)

        emails.append({
            "id": message_id,
            "raw": decoded_email
        })

    return emails


def delete_message(message_id):
    service = get_service()

    service.users().messages().delete(
        userId="me",
        id=message_id
    ).execute()