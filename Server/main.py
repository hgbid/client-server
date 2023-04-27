from src.requests import *
import selectors
import socket
import os

sel = selectors.DefaultSelector()


def get_port():
    port = PORT
    try:
        with open("port.info", "r") as f:
            port = int(f.read())
    except FileNotFoundError:
        print("- File 'port.info' not found. The default port has been set.")
    except Exception as e:
        print("Error. The default port has been set.")
    return port


def accept(sock, mask):
    connection, client_address = sock.accept()
    print('@ Connection from', client_address)
    connection.setblocking(False)
    sel.register(connection, selectors.EVENT_READ, read)


def read(conn, mask):
    try:
        data = conn.recv(1024)

        if data:
            text = data.decode("utf-8")
            print("\n@ Received message: " + text.replace('\n', '').replace(" ", ''))

            reply = handle_requests(text, conn)
            replydata = bytearray(reply, "utf-8")
            newdata = bytearray(1024)
            for i in range(min(len(replydata), len(newdata))):
                newdata[i] = replydata[i]
            conn.sendall(newdata)

        else:
            print('closing', conn)
            sel.unregister(conn)
            conn.close()

    except Exception as e:
        print('closing', conn)
        sel.unregister(conn)
        conn.close()
        print('Waiting for a connection...')


def define_sock():
    port = get_port()
    sock = socket.socket()
    sock.bind((HOST, port))
    sock.listen(10)
    sock.setblocking(False)
    return sock


if __name__ == "__main__":
    try:
        os.mkdir("files\\")
    except: pass

    if not os.path.isfile("server.db"):
        print("- 'File server.db' is not exist.\n- Creating new db")
        create_tables()     # create DB tables
    else:
        load_tables()

    sock = define_sock()
    sel.register(sock, selectors.EVENT_READ, accept)
    print('Waiting for a connection...')

    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data
        callback(key.fileobj, mask)
