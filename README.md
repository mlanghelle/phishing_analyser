# Phishing Email Analyzer

An open-source tool that allows users to forward suspicious emails
to a designated email address and receive an automated analysis
of whether the email is likely to be phishing.

The project is designed with privacy and transparency in mind.
Users can run their own instance and configure their own email provider.

## How It Works

1. Forward a suspicious email to the analyzer email address.
2. The application retrieves the email.
3. The email is parsed and relevant information is extracted.
4. The extracted information is analyzed for phishing indicators.
5. The user receives a report containing the analysis and risk assessment.

## Prerequisites

Before running the application, you must configure an email service
for retrieving incoming messages.

See email_provider.py for instructions on setting up your chosen
email provider.

I recommend setting up a separate email address for this purpose,
as the current implementation deletes incoming messages after
retrieving them.