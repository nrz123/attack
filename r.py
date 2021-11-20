import socket
import ssl
import threading
import uuid
client_context=ssl._create_unverified_context(certfile='cert.crt',keyfile='id_rsa',cafile='ca.crt')
def http_socket(client,addr):
    client=client_context.wrap_socket(client,server_side=True)
    filename=str(uuid.uuid1())
    print(filename)
    f = open(filename, "wb")
    while True:
        req = client.recv(65536)
        if (not req):
            f.close()
            client.close()
            print('close')
            return
        f.write(req)
sock_server = socket.socket()
sock_server.bind(("0.0.0.0", 8000))
sock_server.listen(65536)
while True:
    threading.Thread(target=http_socket, args=sock_server.accept()).start()
