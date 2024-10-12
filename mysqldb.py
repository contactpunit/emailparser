import mysql.connector
import os
from mysql.connector import Error
from fastapi import HTTPException

class MysqlDb:
    _activeInstance = None

    def __new__(cls):
        if cls._activeInstance is None:
            cls._activeInstance = super(MysqlDb, cls).__new__(cls)
            host = '127.0.0.1'
            user = os.getenv('SQLUSER', 'default_user')
            password = os.getenv('SQLPASS', 'default_pass')
            database = os.getenv('DATABASE', 'credentials')

            print(f"Connecting to database with Host: {host}, User: {user}, Database: {database}")

            cls._activeInstance.connection = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                database=database
            )
        return cls._activeInstance
    
    def __init__(self) -> None:
        self.cursor = self.connection.cursor(dictionary=True)
    
    def is_connected(self):
        return self.connection.is_connected() if self.connection else False
    
    def execute_query(self, query, values):
        try:
            self.cursor.execute(query, values)
            self.connection.commit()
            if self.cursor.rowcount > 0:
                return f"Update successful: {self.cursor.rowcount} rows affected."
            else:
                return "No rows were affected."
        except Error as e:
            raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")
    
    def disconnect(self):
        if self.connection is not None and self.connection.is_connected():
            self.connection.close()
            self.connection = None

db = MysqlDb()

