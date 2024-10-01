import os.path
import json
import mysql.connector
import base64
import argparse
from datetime import datetime
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://mail.google.com/']

def connect_db(username, password):
    connection = mysql.connector.connect(
        host="localhost",
        user=username,
        password=password,
        database='credentials'
    )
    cursor = connection.cursor(dictionary=True)
    return (cursor, connection)

def create_creds(token, refresh_token, token_uri, client_id, client_secret, scopes, account, expiry, universe_domain):
    date_obj = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S.%fZ")
    cred = Credentials(
                token=token,
                refresh_token=refresh_token,
                token_uri=token_uri,
                client_id=client_id,
                client_secret=client_secret,
                scopes=scopes,
                account=account,
                expiry=date_obj,
                universe_domain=universe_domain
            )
    return cred

def create_flow(project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope):
    client_secrets = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": redirect_uris,
            "auth_uri": auth_uri,
            "token_uri": token_uri,
            "project_id": project_id,
            "auth_provider_x509_cert_url": auth_provider_x509_cert_url
        }
    }
    flow = InstalledAppFlow.from_client_config(client_secrets, scopes=SCOPES)
    return flow

def get_credfields_from_db(username, password):
    cursorObj = connect_db(username, password)
    cursor = cursorObj[0]
    connection = cursorObj[1]
    sql = "SELECT emailid, auth_uri, project_id, token_uri, redirect_uris, client_id, client_secret, auth_provider_x509_cert_url, scope FROM mailcreds"
    cursor.execute(sql)
    result = cursor.fetchone()
    redirect_uris=result.get('redirect_uris')
    auth_uri=result['auth_uri']
    token_uri=result['token_uri']
    client_id=result['client_id']
    client_secret=result['client_secret']
    project_id=result['project_id']
    scope=result['scope']
    auth_provider_x509_cert_url=result['auth_provider_x509_cert_url']
    project_id=result['project_id']
    cursor.close()
    connection.close()
    return (project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope)

def get_tokens_from_db(username, password):
    cursorObj = connect_db(username, password)
    cursor = cursorObj[0]
    connection = cursorObj[1]
    sql = "SELECT access_token, refresh_token, token_uri, client_id, client_secret, scopes, universe_domain, account, expiry FROM tokens ORDER BY id DESC LIMIT " + str(args.fetchnum)
    cursor.execute(sql)
    result = cursor.fetchone()
    if result:
        cursor.close()
        connection.close()
        return result
    else:
        return None

def generate_token(username, password):
    (project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope) = get_credfields_from_db(username, password)
    flow = create_flow(project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope)
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

    insertOrUpdateTokenRecord(username, password, token, client_id, client_secret)
    return creds


def insertOrUpdateTokenRecord(username, password, token, client_id, client_secret):
    expiry_at = token['expires_at']
    expiry_utc = datetime.utcfromtimestamp(expiry_at)
    expiry_iso = expiry_utc.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'
    cursorObj = connect_db(username, password)
    cursor = cursorObj[0]
    connection = cursorObj[1]
    result = get_tokens_from_db(username, password)
    if not result:
        scope = ['https://mail.google.com/']
        insert_data = {
            'access_token': token['access_token'],
            'refresh_token': token.get('refresh_token'),
            'expiry': expiry_iso,
            'id': 1,
            'token_uri': 'https://oauth2.googleapis.com/token',
            'client_id': client_id,
            'client_secret': client_secret,
            'scopes': json.dumps(scope),
            'universe_domain': 'googleapis.com',
            'account': ''
        }
        columns = columns = ', '.join(insert_data.keys())
        placeholders = ', '.join(['%s'] * len(insert_data))
        sql = f"INSERT INTO tokens ({columns}) VALUES ({placeholders})"
        values = tuple(str(value) if isinstance(value, list) else value for value in insert_data.values())
        cursor.execute(sql, values)
        connection.commit()
    else:
        update_data = {
            'access_token': token['access_token'],
            'refresh_token': token.get('refresh_token'),
            'expiry': expiry_iso
        }
        columns = ', '.join(f"{key} = %s" for key in update_data.keys())
        sql = f"UPDATE tokens SET {columns} WHERE id = 1"
        values = list(update_data.values())
        cursor.execute(sql, values)
        connection.commit()

def get_token(credObj, username, password):
    if not credObj or not credObj.valid:
        if credObj and credObj.expired and credObj.refresh_token:
            try:
                credObj.refresh(Request())
            except Exception as e:
                print('regenerating token')
                credObj = generate_token(username, password)
                return credObj
        else:
            (project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope) = get_credfields_from_db(username, password)
            flow = create_flow(project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret, scope)
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
            credObj = creds
    return credObj

def read_messages(allMessages, mail_service):
    messages = allMessages.get('messages', [])
    if not messages:
        print("No new messages.")
    else:
        for msg in messages:
            # Get the message from its id
            msgTxt = mail_service.users().messages().get(userId='me', id=msg['id']).execute()
            try:
                payload = msgTxt['payload']
                headers = payload['headers']

                for d in headers:
                    if d['name'] == 'Subject':
                        subject = d['value']
                        print(subject)
                    if d['name'] == 'From':
                        sender = d['value']
                        print(sender)
                parts = payload.get('parts')[0]
                data = parts['body']['data']
                data = data.replace("-","+").replace("_","/")
                decoded_data = base64.b64decode(data)
                print(decoded_data)
                print('=============')
            except:
                pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to fetch gmails using oauth Api and perform diferent actions",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    option1 = parser.add_argument_group('Option 1: Fetch Messages')
    option1.add_argument('--fetchMessages', type=bool, help='fetch messages rom mailbox')
    option1.add_argument('--fetchnum', type=int, help='number of messages to display')

    option2 = parser.add_argument_group('Option 3: Save Messages')
    option2.add_argument('--saveMessages', type=bool, help='save messages in db')
    option2.add_argument('--savenum', type=int, help='number of messages to save in db')

    parser.add_argument('--username', type=str, required=True, help='db username')
    parser.add_argument('--password', type=str, required=True, help='db password')

    args = parser.parse_args()

    option1_provided = args.fetchMessages is not None and args.fetchnum is not None
    option2_provided = args.saveMessages is not None and args.savenum is not None

    if not (option1_provided or option2_provided):
        parser.error("Either Option 1 or Option 2 must be provided.")
    
    if (option1_provided and option2_provided ):
        parser.error("Only one of Options can be provided.")

    if option1_provided and not all([args.fetchMessages is not None, args.fetchnum is not None]):
        parser.error("Both fetchMessages and fetchnum must be provided in Group 1.")

    if option2_provided and not all([args.saveMessages is not None, args.savenum is not None]):
        parser.error("Both saveMessages and savenum must be provided in Group 3.")

    if option1_provided:
        result = get_tokens_from_db(args.username, args.password)
        if result:
            token=result['access_token']
            refresh_token=result.get('refresh_token')
            token_uri=result['token_uri']
            client_id=result['client_id']
            client_secret=result['client_secret']
            scopes=result['scopes']
            account=result['account']
            expiry=result['expiry']
            universe_domain=result['universe_domain']
        
            if all([token, refresh_token, token_uri, client_id, client_secret, scopes, expiry, universe_domain]):
                credObj = create_creds(token, refresh_token, token_uri, client_id, client_secret, scopes, account, expiry, universe_domain)
                cred = get_token(credObj, args.username, args.password)
                mail_service = build('gmail', 'v1', credentials=cred)
                results = mail_service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=args.fetchnum).execute()
                read_messages(results, mail_service)
            else:
                print('some data missing')
                
        else:
            credObj = generate_token(args.username, args.password)
            print(credObj)

    if option2_provided:
        pass

