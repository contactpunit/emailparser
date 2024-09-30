import os.path
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://mail.google.com/']

def authenticate_gmail():
    creds = None
    token_file = 'token.json'
    if os.path.exists(token_file):
        with open(token_file, 'r') as token:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # not using webserver but local desktop - settings for redirect_url
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
            auth_url, _ = flow.authorization_url(prompt='consent')
            print('please go to this url and authorize app', auth_url)
            code = input('enter auth code here: ')
            token = flow.fetch_token(code=code)
            creds = Credentials(
                token=token['access_token'],
                refresh_token=token.get('refresh_token'),
                token_uri=flow.client_config['token_uri'],
                client_id=flow.client_config['client_id'],
                client_secret=flow.client_config['client_secret'],
                scopes=SCOPES
            )
        
        with open(token_file, 'w') as token:
            token.write(creds.to_json())

    return creds

if __name__ == '__main__':
    credential_object = authenticate_gmail()
    gmail_service = build('gmail', 'v1', credentials=credential_object)
    print('Access Token: ', gmail_service)

    results = gmail_service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print("No new messages.")
    else:
        for message in messages:
            print(f"Message ID: {message['id']}")
