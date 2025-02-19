import pymysql
#sys.path gets appended in routes.py
from constants import * 

db_error = None

# Establish a connection to the database.
# Return None if an error occurs
def db_connect():
    try:
        conn = pymysql.connect(user=PYMYSQL_USER,
                               passwd=PYMYSQL_PASS,
                               db=DB_NAME,
                               host=DB_HOST)
        cur = conn.cursor(pymysql.cursors.DictCursor)
    except Exception as e:
        db_error = e
        conn, cur = None, None

    return conn, cur
