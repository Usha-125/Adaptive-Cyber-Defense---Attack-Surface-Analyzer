import ssl

def grab_banner(sock, port, target):
    try:
        if port == 80:
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            return sock.recv(1024).decode(errors="ignore")

        elif port == 443:
            context = ssl.create_default_context()
            secure_sock = context.wrap_socket(sock, server_hostname=target)
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            secure_sock.send(request.encode())
            return secure_sock.recv(1024).decode(errors="ignore")

        elif port in [21, 22, 25, 110, 143]:
            return sock.recv(1024).decode(errors="ignore")

        else:
            return None

    except:
        return None