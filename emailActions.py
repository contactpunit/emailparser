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

class Mailbox:
    def __init__(self, dbconnection, mail_service) -> None:
        self.dbObject = dbconnection
        self.mail_service= mail_service
        self.table = 'mailbox'
    
    def save_message(self, msgDetail):
        fields = ('messageid',)
        try:
            result = self.dbObject.get_mailbox_fields(self.table, *fields)
            if not result:
                insert_data = {
                    'client_id': client_id,
                    'folder': msgDetail['folder'],
                    'subject': msgDetail['subject'],
                    'messageid': msgDetail['messageid'],
                    'body': msgDetail['body']
                }
                self.dbObject.insert_data('mailbox', insert_data)
        except Exception as e:
            print("Error occurred during get operation:", e)

    def get_message(self, message, save) -> None:
        msgTxt = self.mail_service.users().messages().get(userId='me', id=message['id']).execute()
        try:
            msgDetail = {'subject': '', 'from': '', 'msgId': '', 'body': '', 'folder': 'INBOX'}
            payload = msgTxt['payload']
            headers = payload['headers']
            for h in headers:
                if h['name'] == 'Subject':
                    msgDetail['subject'] = h['value']
                if h['name'] == 'From':
                    msgDetail['from'] = h['value']
                if h['name'] == 'Message-ID':
                    msgDetail['messageid'] = h['value']
            parts = payload.get('parts')[0]
            data = parts['body']['data']
            data = data.replace("-","+").replace("_","/")
            decoded_data = base64.b64decode(data)
            msgDetail['body'] = decoded_data
            if not save:
                print(f"Subject: {msgDetail['subject']}")
                print(f"From: {msgDetail['from']}")
                print(f"Body: {msgDetail['body']}")
                print('=============')
            else:
                self.save_message(msgDetail)
        except Exception as e:
            print(e)

    def read_messages(self, folder, num_messages, save):
        results = self.mail_service.users().messages().list(userId='me', labelIds=[folder], maxResults=num_messages).execute()
        messages = results.get('messages', [])
        if not messages:
            print('no new messages')
        else:
            for message in messages:
                self.get_message(message, save)

    def delete_messages(self):
        pass

class Tokens:
    def __init__(self, dbconnection, **kwargs) -> None:
        for key, value in kwargs.items():
            if key == 'expiry':
                date_obj = datetime.strptime(kwargs['expiry'], "%Y-%m-%dT%H:%M:%S.%fZ")
                self.expiry = date_obj
            else:
                setattr(self, key, value)
        self.account = ''
        self.cred = None
        # using composition
        self.dbObject = dbconnection
    
    def create_credobject_from_tokenparams(self):
        self.cred = Credentials(
                token=self.token,
                refresh_token=self.refresh_token,
                token_uri=self.token_uri,
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=SCOPES,
                account='',
                expiry=self.expiry,
                universe_domain=self.universe_domain
            )
    
    def build_mailservice(self):
        mail_service = build('gmail', 'v1', credentials=self.cred)
        return mail_service
    
    def create_token_from_dbcreds(self):
        fields = ('emailid', 'auth_uri', 'project_id', 'token_uri', 'redirect_uris', 'client_id', 'client_secret', 'auth_provider_x509_cert_url', 'scope')
        result = self.dbObject.get_credtable_fields('mailcreds', *fields)
        project_id = result['project_id']
        auth_provider_x509_cert_url = result['auth_provider_x509_cert_url']
        token_uri = result['token_uri']
        auth_uri = result['auth_uri']
        redirect_uris = result['redirect_uris']
        client_id = result['client_id']
        client_secret = result['client_secret']
        flow = self.create_flow(project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret)
        flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
        auth_url, _ = flow.authorization_url(prompt='consent')
        print('please go to this url and authorize app', auth_url)
        code = input('enter auth code here: ')
        token = flow.fetch_token(code=code)
        return (token, flow)
    
    def create_flow(self, project_id, auth_provider_x509_cert_url, token_uri, auth_uri, redirect_uris, client_id, client_secret):
        flow_params = {
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
        flow = InstalledAppFlow.from_client_config(flow_params, scopes=SCOPES)
        return flow

    def generate_token_and_credsObject(self):
        token, flow = self.create_token_from_dbcreds()
        self.client_id = flow.client_config['client_id']
        self.client_secret = flow.client_config['client_secret']
        creds = Credentials(
            token=token['access_token'],
            refresh_token=token.get('refresh_token'),
            token_uri=flow.client_config['token_uri'],
            client_id=flow.client_config['client_id'],
            client_secret=flow.client_config['client_secret'],
            scopes=SCOPES
        )
        self.cred = creds
        self.insertOrUpdateTokenRecord(token)
        print('creds generated')

    def insertOrUpdateTokenRecord(self, token):
        expiry_at = token['expires_at']
        expiry_utc = datetime.utcfromtimestamp(expiry_at)
        expiry_iso = expiry_utc.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z'
        fields = ('client_id', 'access_token')
        result = self.dbObject.get_tokens('tokens', *fields)
        if not result:
            insert_data = {
                'access_token': token['access_token'],
                'refresh_token': token.get('refresh_token'),
                'expiry': expiry_iso,
                'id': 1,
                'token_uri': 'https://oauth2.googleapis.com/token',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scopes': json.dumps(SCOPES),
                'universe_domain': 'googleapis.com',
                'account': ''
            }
            self.dbObject.insert_data('tokens', insert_data)
        else:
            update_data = {
                'access_token': token['access_token'],
                'refresh_token': token.get('refresh_token'),
                'expiry': expiry_iso
            }
            self.dbObject.update_data('tokens','client_id', client_id, update_data)

    def validateRefreshCredObject(self):
        if not self.cred or not self.cred.valid:
            if self.cred and self.cred.expired and self.cred.refresh_token:
                try:
                    self.cred.refresh(Request())
                except Exception as e:
                    print('Unable to refresh, will regenerating new token')
                    self.generate_token_and_credsObject()
            else:
                token, flow = self.create_token_from_dbcreds()
                cred = Credentials(
                    token=token['access_token'],
                    refresh_token=token.get('refresh_token'),
                    token_uri=flow.client_config['token_uri'],
                    client_id=flow.client_config['client_id'],
                    client_secret=flow.client_config['client_secret'],
                    scopes=SCOPES
                )
                if cred:
                    self.cred = cred
        else:
            self.generate_token_and_credsObject()
class MysqlDb:
    _activeInstance = None

    def __new__(cls, config):
        if cls._activeInstance is None:
            cls._activeInstance = super(MysqlDb, cls).__new__(cls)
            try:
                cls._activeInstance.connection = mysql.connector.connect(**config)
                cls._activeInstance.cursor = cls._activeInstance.connection.cursor(dictionary=True)
                print("Database connection established.")
            except Exception as e:
                print(f"Error: {e}")
                cls._activeInstance = None
        return cls._activeInstance
    
    def close(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
            print("Database connection closed.")

    def get_cursor(self):
        return self.cursor

class DbConnect:
    def __init__(self, config) -> None:
        self.connect = MysqlDb(config)
        self.username = config.get('username')
        self.password = config.get('password')

    def get_credtable_fields(self, table, *fields):
        cursor = self.connect.get_cursor()
        columns = ', '.join(fields)
        sql = f"SELECT {columns} from {table}" # fields requested emailid, auth_uri, project_id, token_uri, 
        # redirect_uris, client_id, client_secret, auth_provider_x509_cert_url, scope
        try:
            cursor.execute(sql)
            results = cursor.fetchone()
            return results
        except Exception as e:
            print("Error occurred during get operation:", e)
    
    def get_mailbox_fields(self, table, *fields):
        cursor = self.connect.get_cursor()
        columns = len(fields) == fields[0] if len(fields) == 1 else ', '.join(fields)
        sql = f"SELECT {columns} from {table}"
        try:
            cursor.execute(sql)
            results = cursor.fetchone()
            return results
        except Exception as e:
            print("Error occurred during get operation:", e)

    def get_tokens(self, table, *fields):
        cursor = self.connect.get_cursor()
        columns = ', '.join(fields)
        sql = f"SELECT {columns} FROM {table} ORDER BY id DESC LIMIT 1"
        try:
            cursor.execute(sql)
            results = cursor.fetchone()
            return results
        except Exception as e:
            print("Error occurred during get operation:", e)
    
    def insert_data(self, table, data):
        cursor = self.connect.get_cursor()
        if isinstance(data, dict):
            columns = ', '.join(data.keys())
            placeholders = ', '.join(['%s'] * len(data))
            sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            values = tuple(str(value) if isinstance(value, list) else value for value in data.values())
            try:
                cursor.execute(sql, values)
                self.connect.connection.commit()
            except Exception as e:
                print("Error occurred during get operation:", e)
        else:
            print("Provided input is not a dictionary.")

    def update_data(self, table, match_field, match_value, data):
        cursor = self.connect.get_cursor()
        if isinstance(data, dict):
            columns = ', '.join(f"{key} = %s" for key in data.keys())
            sql = f"UPDATE {table} SET {columns} WHERE {match_field} = %s"
            values = list(data.values())
            values.append(match_value)
            try:
                cursor.execute(sql, values)
                self.connect.connection.commit()
            except Exception as e:
                print("Error occurred during get operation:", e)
        else:
            print("Provided input is not a dictionary.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Script to fetch gmails using oauth Api and perform diferent actions")
    option1 = parser.add_argument_group('Option 1: Fetch Messages')
    option1.add_argument('--fetchMessages', type=bool, help='fetch messages rom mailbox')
    option1.add_argument('--fetchnum', type=int, help='number of messages to display')
    option1.add_argument( '-x' , '--save', action='store_true', default=False, help='save message/messages to db')

    option2 = parser.add_argument_group('Option 2: Delete Messages')
    option2.add_argument('--deleteMessages', type=bool, help='save messages in db')
    option2.add_argument('--delnum', type=int, help='number of messages to delete')
    option2.add_argument('--folder', type=str, help='folder name')

    parser.add_argument('--username', type=str, required=True, help='db username')
    parser.add_argument('--password', type=str, default=os.getenv('OAUTHPASS', 'default_password'), help='db password')

    args = parser.parse_args()

    option1_provided = args.fetchMessages is not None and args.fetchnum is not None
    option2_provided = args.deleteMessages is not None and args.delnum is not None

    if not (option1_provided or option2_provided):
        parser.error("Either Option 1 or Option 2 must be provided.")
    
    if (option1_provided and option2_provided):
        parser.error("Only one of Options can be provided.")

    if option1_provided and not all([args.fetchMessages is not None, args.fetchnum is not None]):
        parser.error("Both fetchMessages and fetchnum must be provided in Group 1.")

    if option2_provided and not all([args.deleteMessages is not None, args.delnum is not None]):
        parser.error("Both deleteMessages and delnum must be provided in Group 2.")

    if option1_provided:
            config = {
            'host': 'localhost',
            'database': 'credentials',
            'user': args.username,
            'password': args.password
        }
            dbconnection = DbConnect(config)
            fields = ('access_token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes', 'universe_domain', 'expiry')
            result = dbconnection.get_tokens('tokens', *fields)
            if result:
                token=result['access_token']
                refresh_token=result.get('refresh_token')
                token_uri=result['token_uri']
                client_id=result['client_id']
                client_secret=result['client_secret']
                scopes=result['scopes']
                account=''
                expiry=result['expiry']
                universe_domain=result['universe_domain']

                if all([token, refresh_token, token_uri, client_id, client_secret, scopes, expiry, universe_domain]):
                    params = {
                        'token': token,
                        'refresh_token': refresh_token,
                        'token_uri': token_uri,
                        'client_id': client_id,
                        'client_secret': client_secret,
                        'scopes': scopes,
                        'expiry': expiry,
                        'universe_domain': universe_domain
                    }
                    newToken = Tokens(dbconnection, **params)
                    newToken.create_credobject_from_tokenparams()
                    newToken.validateRefreshCredObject()
                    mail_service = newToken.build_mailservice()
                    mailboxobject = Mailbox(dbconnection, mail_service)
                    mailboxobject.read_messages('INBOX', args.fetchnum, args.save)
                    db_connection = MysqlDb(config)
                    db_connection.close()
            else:
                newToken = Tokens(dbconnection)
                newToken.generate_token_and_credsObject()
                mail_service = newToken.build_mailservice()
                mailboxobject = Mailbox(dbconnection, mail_service)
                mailboxobject.read_messages('INBOX', args.fetchnum, args.save)
                db_connection = MysqlDb(config)
                db_connection.close()
    if option2_provided:
        pass
