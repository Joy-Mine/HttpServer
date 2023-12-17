import socket
import threading
import stat
import mimetypes
import urllib.parse
import http.cookies
import argparse
import os
import mimetypes
class HTTPServer:

    def run_server(self, host, port):
       print(f"Server Started at http://{host}:{port}")
       self.host = host
       self.port = port
    
    def setup_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(128)
    
    def shutdown(self):
        self.socket.close()
    
    def accept_request(self,client_socket,client_address):
        print(f"Accept request from {client_address}")
        request = client_socket.recv(4096).decode('utf-8')
        # handle request
        response = self.handle_request(request)
        client_socket.send(response.encode('utf-8'))

        client_socket.shutdown(1)
        client_socket.close()
    
    def handle_request(self, request):
        # 将得到的data转为一行一行的列表
        format_request = request.strip().split('\r\n')
        # 将请求行分割
        request_headline = format_request[0].split()
        # 请求的文件
        request_file = request_headline[1][1:]
       
        if len(request_headline) == 3:
            method, path, protocol = request_headline
            if method == 'GET':
                return self.handle_get(request_file)
            elif method == 'POST':
                return self.handle_post(request_file)
            else:
                return self.method_not_allowed()
                # 405 Method Not Allowedhandle_error(405)
    
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
        parser = argparse.ArgumentParser(description='Simple HTTP Server')
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

