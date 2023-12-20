import socket
from threading import Thread
import mimetypes
import argparse
import os
import mimetypes


class HTTPServer:
    
    def run_server(self, host, port):
        print(f"Server Started at http://{host}:{port}")
        # self.host = host
        # self.port = port

        # set_up
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(128)

        #accept_request    def accept_request(self,client_socket,client_address):
        while True:
            client_sock, client_address=self.sock.accept()
            # Thread.start(target=self.handle_request, args=(client_sock,client_address))
            Thread(target=self.handle_request, args=(client_sock,client_address)).start
        
        #shut_down
        if self.sock is not None:
            self.sock.shutdown()
            self.sock.close()

    
    def handle_request(self, client_sock, client_address):
        try:
            print(f"Accept request from {client_address}")
            response=None
            request = client_sock.recv(4096).decode('utf-8')
            
            request_lines = request.strip().split('\r\n')
            request_headline = request_lines[0].split()
            
            # request_file = request_headline[1][1:]
        
            if len(request_headline) == 3:
                method, path, protocol = request_headline
                if method == 'GET':
                    return self.handle_get(path)
                elif method == 'HEAD':
                    response = self.handle_head(path)
                elif method == 'POST':
                    request_body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''
                    response = self.handle_post(path, request_body)
                else:
                    return self.method_not_allowed()
                    # 405 Method Not Allowedhandle_error(405)
            else:
                response="HTTP/1.1 400 Bad Request\r\n\r\n"
            
        except Exception as e:
            print(f"Error handling request: {e}")
            response = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
        finally:
            client_sock.send(response.encode('utf-8'))
            client_sock.shutdown(1)
            client_sock.close()
    
    def has_permission_other(file_path):
        # Implement the logic to check if the file has permission for others.
        # Return True if it has permission, False otherwise.
        file_stat = os.stat(file_path)
        return file_stat.st_mode & 0o004
    
    def get_file_mime_type(file_extension):
        # 不保证正确
        # Implement the logic to get the mime type of the file.
        # Return the mime type.
        return mimetypes.types_map[file_extension]

    def handle_get(self, request_file):
        if (not os.path.exists(request_file)) or (not os.path.isfile(request_file)):
            return self.resource_not_found()
            # 404 Not Found
        elif(not self.has_permission_other(request_file)):
            return self.resource_forbidden()
            # 403 Forbidden
        else:
            builder = ResponseBuilder()

            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header("Content-Type", self.get_file_mime_type(request_file.split(".")[1]))

            return builder.build()
        
    def handle_post(self, request_file):
        if (not os.path.exists(request_file)) or (not os.path.isfile(request_file)):
            return self.resource_not_found()
            # 404 Not Found
        elif(not self.has_permission_other(request_file)):
            return self.resource_forbidden()
            # 403 Forbidden
        else:
            builder = ResponseBuilder()

            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            builder.add_header("Content-Type", self.get_file_mime_type(request_file.split(".")[1]))
            # 不确定是不是对的，直接返回文件
            builder.set_body(request_file)

            return builder.build()    






    def method_not_allowed(self):
        """
        Returns 405 not allowed status and gives allowed methods.
        TODO: If you are not going to complete the `ResponseBuilder`,
        This must be rewritten.
        """
        builder = ResponseBuilder()
        builder.set_status("405", "METHOD NOT ALLOWED")
        allowed = ", ".join(["GET", "POST"])
        builder.add_header("Allow", allowed)
        builder.add_header("Connection", "close")
        return builder.build()


    def get_file_contents(file_path):
        with open(file_path, 'r') as file:
            return file.read()

    def resource_not_found(self):
        """
        Returns 404 not found status and sends back our 404.html page.
        """
        mime_types = mimetypes.types_map
        builder = ResponseBuilder()
        builder.set_status("404", "NOT FOUND")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mime_types["html"])
        builder.set_content(os.get_file_contents("404.html"))
        return builder.build()

    def resource_forbidden(self):
        """
        Returns 403 FORBIDDEN status and sends back our 403.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("403", "FORBIDDEN")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", mimetypes.types_map["html"])
        builder.set_content(os.get_file_contents("403.html"))
        return builder.build()

        
    

    
    



    if __name__ == '__main__':
        parser = argparse.ArgumentParser(description='HTTP Server')
        parser.add_argument('-i', '--host', type=str, default='localhost', help='Host name or IP address')
        parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
        args = parser.parse_args()
        run_server(args.host, args.port)


class ResponseBuilder:
    def __init__(self):
        self.response = ''
        self.status = None
        self.headerline = ''
        self.body = ''
    
    def set_status(self, status_code, status_text):
       # 生成状态行
       self.status = f"HHTP/1.1 {status_code} {status_text}"
    
    def set_header(self, key, value):
        # 生成首部行
        self.headerline += f'{key}: {value}' + '\r\n'
    
    def set_body(self, body):
        if isinstance(body, (bytes, bytearray)):
            self.body = body
        else:
            self.body = body.encode('utf-8')
    
    def build(self):
        # 生成响应报文
        self.response = self.status + '\r\n'
        self.response += self.headerline
        self.response += '\r\n'
        self.response += '\r\n'
        response = self.response.encode('utf-8')

        # 如果body是文件，直接返回
        response += self.body

        return self.response

