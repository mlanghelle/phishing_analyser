"""
Email provider interface.

This file handles connecting to the email provider and retrieving
incoming messages.

The current implementation uses the Gmail API. Users need to provide
their own credentials.json. token.json is generated locally after
authentication.

get_messages() returns a list containing the message ID and raw email.
delete_message() deletes a processed message from the inbox.
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