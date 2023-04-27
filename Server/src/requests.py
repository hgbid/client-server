import base64
import time
import uuid

import socket
from src.constants import *
from src.db import *
from src.crypt import *


def make_result(ans_code, payload):
    payload_str = str(payload).replace('b\'', '').replace('==\'', '==')
    payload_len = str(len(payload_str))
    return SERVER_VERSION + ans_code + payload_len + payload_str


def register_client(client_name):
    uuid_ = uuid.uuid4()
    client_ID = uuid_.hex
    print("- Client ID Generated")
    insert_into_Client_table(client_ID, client_name, "", "")
    print("- Sending CID...")
    return make_result(REGISTER_SUCCEED_CODE, client_ID)


def get_public_key(pub_key, cid):
    aes_key_b64, encrypted_aes_key = generate_aes(pub_key)
    update_Client_table(cid, pub_key, aes_key_b64)

    print("AES key encrypted.\
          \nSending encrypt AES key...")
    return make_result(SEND_ENCRYPT_AES, encrypted_aes_key)


def get_enc_file_content(conn, file_size):
    # Receive the file contents from the client and save to disk
    bytes_received = 0
    file_content = ''
    while bytes_received < file_size:
        try:
            data = conn.recv(BUFFER_SIZE)
            file_content += data.decode()
            bytes_received += len(data)
        except BlockingIOError as e:
            if e.errno == 10035:
                time.sleep(0.1)
            else:
                raise
    return file_content


def get_file(cid, data, conn, first):
    if first:
        file_size_bytes = data[:FILESIZE_SIZE].replace(" ", '')
        filename = data[FILESIZE_SIZE:FILESIZE_SIZE + FILENAME_SIZE].replace(" ", '')
        file_size = int(file_size_bytes)
    else:
        filename = data.replace(" ", '')
        file_size = get_file_size(cid)

    print("- Receiving file " + filename + " of size " + str(file_size) + " bytes...")
    file_content = get_enc_file_content(conn, file_size)

    with open('files/' + filename, 'wb') as f:
        aes_key = base64.b64decode(get_client_aes(cid))
        cipher = AES.new(aes_key, AES.MODE_CBC, b'\x00' * AES.block_size)
        f.write(bytearray(decrypted_aes_message(cipher, file_content)))
    print('- File received and saved to disk')

    insert_into_File_table(cid, filename, 'files/', str(0), file_size)
    update_lastseen(cid)

    crc_server = crc32(filename).upper()
    payload = filename + ' ' * (FILENAME_SIZE - len(filename)) + crc_server
    print('- Sending CRC...')
    return make_result(GOT_FILE, payload)


def update_crc_status(cid, data):
    filename = data[FILESIZE_SIZE + 1:FILESIZE_SIZE + FILENAME_SIZE].replace(" ", '')
    update_crc_db(cid, filename)

    update_lastseen(cid)
    return make_result(GOT_FILE, cid)


def reconnect(cid):
    pub_key = get_db_public_key(cid)
    aes_key_b64, encrypted_aes_key = generate_aes(pub_key)
    update_Client_table(cid, pub_key, aes_key_b64)

    print("- AES key encrypted.\
          \n- Sending encrypt AES key...")
    return make_result(SEND_ENCRYPT_AES, encrypted_aes_key)


def handle_requests(request, conn):
    code = request[CODE_INDEX:SIZE_INDEX]
    cid = request[:VER_INDEX]
    if code == C_REGISTER_CODE:
        print("\tClient: NO_RECOGNIZED. Request: register")
        try:
            print(request)
            return register_client(request[PAYLOAD_INDEX:])
        except:
            print('- Sending register failed massage...')
            return make_result(REGISTER_FAIL_CODE, cid)

    else:
        try:
            name = get_client_name(cid)
            if code == C_SEND_PUBL_KEY_CODE:
                print("\tClient: " + name + ". Request: send RSA public key")
                return get_public_key(pub_key=request[PAYLOAD_INDEX:], cid=request[:VER_INDEX])

            elif code == C_SEND_FILE_CODE:
                print("\tClient: " + name + ". Request: send encrypt file")
                return get_file(cid=request[:VER_INDEX], data=request[PAYLOAD_INDEX - 1:],
                                conn=conn, first=1)

            elif code == C_CRC_OK_CODE:
                print("\tClient: " + name + ". Request: CRC OK")
                return update_crc_status(cid=request[:VER_INDEX], data=request[PAYLOAD_INDEX - 1:])

            elif code == C_RECONNECT_CODE:
                print("\tClient: " + name + ". Request: reconnect")
                return reconnect(cid=request[:VER_INDEX])

            elif code == C_CRC_ERROR_SA_CODE:
                print("\tClient: " + name + ". Request: CRC incorrect. send encrypt file again")
                return get_file(cid=request[:VER_INDEX], data=request[PAYLOAD_INDEX - 1:],
                                conn=conn, first=0)

            elif code == C_CRC_ERROR_END_CODE:
                print("\tClient: " + name + ". Request: CRC incorrect. end trying send the file")
                print('- Sending confirmation...')
                return make_result(OK_END, cid)

        except:
            if code == C_RECONNECT_CODE:
                print("\tClient: NO_RECOGNIZED. Request: reconnect")
                print('- Sending reconnect failed massage...')
                return make_result(RECONNECT_FAILED, cid)
            else:
                print('- Sending general error massage...')
                return make_result(GENERAL_ERROR, cid)

    return "0000"
