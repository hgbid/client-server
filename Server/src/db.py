import sqlite3
from datetime import datetime

Clients_table = {}
Files_table = {}


def create_tables():
    db_conn = sqlite3.connect('server.db')
    db_conn.execute('''CREATE TABLE IF NOT EXISTS Clients
                     (ID CHAR(32) PRIMARY KEY NOT NULL,
                     Name TEXT NOT NULL,
                     PublicKey CHAR(160),
                     LastSeen TEXT,
                     AESKey CHAR(32));''')

    db_conn.execute('''CREATE TABLE IF NOT EXISTS Files
                     (ID CHAR(32) NOT NULL,
                     FileName TEXT NOT NULL,
                     PathName TEXT NOT NULL,
                     Verified INT);''')
    db_conn.commit()
    db_conn.close()


def load_tables():
    db_conn = sqlite3.connect('server.db')
    cur = db_conn.cursor()

    cur.execute("SELECT * FROM Clients;")
    clients = cur.fetchall()
    for c in clients:
        Clients_table[c[0]] = {'Name': c[1], 'PublicKey': c[2],
                               'LastSeen': c[3], 'AESKey': c[4]}

    cur.execute("SELECT * FROM Clients;")
    files = cur.fetchall()
    for f in files:
        Files_table[f[0]] = {'FileName': f[1], 'PathName': f[2],
                             'Verified': f[3]}

    db_conn.close()


def insert_into_Client_table(newID, newName, newPublicKey, newAESKey):
    db_conn = sqlite3.connect('server.db')
    lastSeen = (datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
    db_conn.execute("INSERT INTO Clients (ID,Name ,PublicKey,LastSeen,AESKey)\
                    VALUES( \"" + str(newID) + "\",\"" + newName + "\", \"" + newPublicKey + "\", \"" \
                    + lastSeen + "\", \"" + newAESKey + "\");")
    db_conn.commit()
    db_conn.close()

    Clients_table[newID] = {'Name': newName, 'PublicKey': newPublicKey,
                            'LastSeen': lastSeen, 'AESKey': newAESKey}
    print("- Client " + newName + " added")


def is_filename_exist(filename):
    vals = Files_table.values()
    for val in vals:
        if val['FileName'] == filename:
            return True
    return False


def get_client_name(cid):
    return Clients_table[cid]['Name']


def get_client_aes(cid):
    return Clients_table[cid]['AESKey']


def get_db_public_key(cid):
    return Clients_table[cid]['PublicKey']


def get_file_size(cid):
    return Files_table[cid]['Size']


def update_Client_table(cid, newPublicKey, newAESKey):
    db_conn = sqlite3.connect('server.db')
    lastSeen = (datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
    db_conn.execute("UPDATE Clients \
                    SET  PublicKey = \"" + str(newPublicKey) + "\",\
                          LastSeen = \"" + lastSeen + "\",\
                          AESKey = \"" + str(newAESKey) + "\"\
                    WHERE ID = \"" + str(cid) + "\";")
    db_conn.commit()
    db_conn.close()

    Clients_table[cid]['PublicKey'] = newPublicKey
    Clients_table[cid]['AESKey'] = newAESKey
    print("- Client " + get_client_name(cid) + " updated 'PublicKey' and 'AESKey'")


def insert_into_File_table(newID, newFileName, newPathName, newVerified, file_size):
    db_conn = sqlite3.connect('server.db')
    db_conn.execute("INSERT INTO Files (ID, FileName, PathName, Verified)\
            VALUES( \"" + str(newID) + "\",\"" + newFileName + "\", \"" + newPathName + "\", " \
                    + newVerified + ");")
    db_conn.commit()
    db_conn.close()
    Files_table[newID] = {'FileName': newFileName, 'PathName': newPathName,
                          'Verified': newVerified, 'Size': file_size}
    print("- File " + newFileName + " added to db")


def update_crc_db(cid, filename):
    db_conn = sqlite3.connect('server.db')
    db_conn.execute("UPDATE Files \
                    SET  Verified = 1\
                    WHERE ID = \"" + str(cid) + "\" AND\
                     FileName = \"" + str(filename) + "\";")
    db_conn.commit()
    db_conn.close()
    Files_table[cid]['Verified'] = 1
    print("- Client " + get_client_name(cid) + " updated CRC status")


def update_lastseen(cid):
    lastSeen = (datetime.now()).strftime("%d/%m/%Y %H:%M:%S")
    db_conn = sqlite3.connect('server.db')
    db_conn.execute("UPDATE Clients \
                    SET  LastSeen = \"" + lastSeen + "\"\
                    WHERE ID = \"" + str(cid) + "\";")
    db_conn.commit()
    db_conn.close()
    Clients_table[cid]['LastSeen'] = lastSeen

    print("- Client " + get_client_name(cid) + " updated 'LastSeen'")


"""
def get_client_name(cid):
    db_conn = sqlite3.connect('server.db')
    cur = db_conn.cursor()
    cur.execute("SELECT Name FROM Clients WHERE ID = \"" + str(cid) + "\";")
    client_name = cur.fetchall()
    db_conn.close()
    return client_name[0][0]


def get_client_aes(cid):
    db_conn = sqlite3.connect('server.db')
    cur = db_conn.cursor()
    cur.execute("SELECT AESKey FROM Clients WHERE ID = \"" + str(cid) + "\";")
    aes_key = cur.fetchall()
    db_conn.close()
    return aes_key[0][0]


def get_db_public_key(cid):
    db_conn = sqlite3.connect('server.db')
    cur = db_conn.cursor()
    cur.execute("SELECT PublicKey FROM Clients WHERE ID = \"" + str(cid) + "\";")
    public_key = cur.fetchall()
    db_conn.close()
    return public_key[0][0]
"""
