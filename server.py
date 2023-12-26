import socket
from threading import Thread
import mimetypes
import argparse
import os
import mimetypes
from datetime import datetime
import base64
import time
import uuid


class HTTPServer:
    
    def run_server(self, host, port, data_dir):
        print(f"Server Started at http://{host}:{port}")

        # set_up
        self.data_dir=data_dir
        self.sessions={}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(128)

        #accept_request    def accept_request(self,client_socket,client_address):
        while True:
            client_sock, client_address=self.sock.accept()
            # Thread.start(target=self.handle_request, args=(client_sock,client_address))
            Thread(target=self.handle_request, args=(client_sock,client_address)).start()
        
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

            headers = {}
            for line in request_lines[1:]:
                if not line:
                    break
                key, value = line.split(': ', 1)
                headers[key] = value
            
            authorization = headers.get('Authorization', None)
            if not authorization or not self.check_authorization(authorization):
                session = headers.get('Cookie', None)
                if not session or not self.check_session(session):
                    response=self.unauthorized_401()
                    return
                username = self.get_session_username(authorization)
                session_id = str(uuid.uuid4())
                expiration_time = time.time() + 360000.0
                self.sessions[session_id] = (username, expiration_time)
                response=self.response_with_cookie(session_id)
            else:
                if len(request_headline) == 3:
                    method, path, protocol = request_headline
                    if method == 'GET':
                        response = self.handle_get(path)
                    elif method == 'HEAD':
                        response = self.handle_head(path)
                    elif method == 'POST':
                        request_body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''
                        response = self.handle_post(path, request_body)
                    else:
                        response=self.method_not_allowed_405({"GET","HEAD","POST"})
                        # 405 Method Not Allowedhandle_error(405)
                else:
                    # response="HTTP/1.1 400 Bad Request\r\n\r\n".encode("utf-8")
                    response=self.bad_request_400()
            
        except Exception as e:
            print(f"Error handling request: {e}")
            # response = "HTTP/1.1 500 Internal Server Error\r\n\r\n".encode("utf-8")
            response=self.server_error_500()
        finally:
            print(response.decode("utf-8"))
            client_sock.send(response)
            client_sock.shutdown(1)
            client_sock.close()
    
    def has_permission_other(self, file_path):
        # real_path = os.path.join(self.data_dir, file_path.strip('/'))
        file_stat = os.stat(file_path)
        return file_stat.st_mode & 0o004
    
    def get_file_mime_type(self, file_extension):
        # 不保证正确
        # Implement the logic to get the mime type of the file.
        # Return the mime type.
        return mimetypes.types_map[file_extension]

    def handle_head(self, file_path):
        real_path = os.path.join(self.data_dir, file_path.strip('/'))
        print(real_path)
        if (not os.path.exists(real_path)):
            return self.not_found_404()
        elif(not self.has_permission_other(real_path)):
            return self.forbidden_403()
        else:
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            # builder.add_header("Content-Type", self.get_file_mime_type(real_path.split(".")[1]))
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            return builder.build()

    def handle_get(self, file_path):
        real_path = os.path.join(self.data_dir, file_path.strip('/'))
        print(real_path)
        if (not os.path.exists(real_path)):
            return self.not_found_404()
        elif(not self.has_permission_other(real_path)):
            return self.forbidden_403()
        else:
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            # builder.add_header("Content-Type", self.get_file_mime_type(real_path.split(".")[1]))
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            return builder.build()
    
    def handle_get(self, file_path):
        real_path = os.path.join(self.data_dir, file_path.strip('/'))
        print(real_path)
        
        if not os.path.exists(real_path):
            return self.not_found_404()
        elif not self.has_permission_other(real_path):
            return self.forbidden_403()
        else:
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")

            if os.path.isfile(real_path):
                with open(real_path, 'rb') as file:
                    builder.set_body(file.read())
                # 可以根据文件类型设置不同的 Content-Type
                # builder.add_header("Content-Type", self.get_file_mime_type(real_path.split(".")[-1]))
            elif os.path.isdir(real_path):
                directory_listing = "<html><body><ul>"
                for item in os.listdir(real_path):
                    directory_listing += f"<li>{item}</li>"
                directory_listing += "</ul></body></html>"
                builder.set_body(directory_listing)
                builder.add_header("Content-Type", "text/html; charset=UTF-8")
            else:
                builder.set_body("<html><body><h1>Unable to handle the request</h1></body></html>")
                builder.add_header("Content-Type", "text/html; charset=UTF-8")
            return builder.build()

    def handle_post(self, file_path, request_body):
        if (not os.path.exists(file_path)):
            return self.resource_not_found()
            # 404 Not Found
        elif(not self.has_permission_other(file_path)):
            return self.resource_forbidden()
            # 403 Forbidden
        else:
            builder = ResponseBuilder()

            builder.set_status("200", "OK")
            builder.add_header("Connection", "close")
            # builder.add_header("Content-Type", self.get_file_mime_type(file_path.split(".")[1]))
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            builder.set_body(file_path)

            return builder.build()    


    def check_session(self, session):
        session_id = session.split("session-id=")[1]
        # Check if the session cookie is valid and not expired
        if session_id in self.sessions:
            _, expiration_time = self.sessions[session_id]
            result = expiration_time > time.time()
            return result
        return False
    def check_user_right(self, session_cookie, user):
        session_name = self.sessions[session_cookie][0]
        print(f'sessionname is {session_name},   user is {user}')
        if session_name != user:
            return False
        else:
            return True
    def check_authorization(authorization):
        credentials = {'client1': '123',
                            'client2':'123',
                            'client3':'123'}
        _, encoded_info = authorization.split(' ')
        decoded_info = base64.b64decode(encoded_info).decode('utf-8')
        print(decoded_info)
        result = False
        username , password = decoded_info.split(":")[0], decoded_info.split(":")[1]
        if username in credentials:
            if password == credentials[username]:
                result = True
        return result
    def get_session_username(auth_header):
        _, encoded_info = auth_header.split(' ')
        decoded_info = base64.b64decode(encoded_info).decode('utf-8')
        username, _ = decoded_info.split(':', 1)
        return username
    
    def response_with_cookie(session_id):
        response_headers = f'HTTP/1.1 200 OK\r\nSet-Cookie: session-id={session_id}; Path=/\r\n\r\n'
        return response_headers.encode('utf-8')



    def get_file_contents(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()
    
    def bad_request_400(self):
        """
        Returns 400 Bad Request status and sends back a 400.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("400", "Bad Request")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", "text/html; charset=utf-8")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        try:
            file_content = self.get_file_contents("400.html")
            builder.set_body(file_content)
        except IOError:
            builder.set_body("<html><body><h1>400 Bad Request</h1></body></html>")
        return builder.build()
    
    def unauthorized_401(self):
        """
        Returns 401 Unauthorized status and sends back a 401.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("401", "Unauthorized")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", "text/html; charset=utf-8")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        try:
            file_content = self.get_file_contents("401.html")
            builder.set_body(file_content)
        except IOError:
            builder.set_body("<html><body><h1>401 Unauthorized</h1></body></html>")
        return builder.build()

    def forbidden_403(self):
        """
        Returns 403 Forbidden status and sends back a 403.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("403", "Forbidden")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", "text/html; charset=utf-8")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        try:
            file_content = self.get_file_contents("403.html")
            builder.set_body(file_content)
        except IOError:
            builder.set_body("<html><body><h1>403 Forbidden</h1></body></html>")
        return builder.build()

    def not_found_404(self):
        """
        Returns 404 Not Found status and sends back a 404.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("404", "Not Found")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", "text/html; charset=utf-8")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        try:
            file_content = self.get_file_contents("404.html")
            builder.set_body(file_content)
        except IOError:
            builder.set_body("<html><body><h1>404 Not Found</h1></body></html>")
        return builder.build()

    def method_not_allowed_405(self, allowed_methods):
        """
        Returns 405 Method Not Allowed status and indicates allowed methods.
        """
        builder = ResponseBuilder()
        builder.set_status("405", "Method Not Allowed")
        builder.add_header("Allow", ", ".join(allowed_methods))
        builder.add_header("Connection", "close")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        builder.set_body("<html><body><h1>405 Method Not Allowed</h1></body></html>")
        return builder.build()

    def server_error_500(self):
        """
        Returns 500 Internal Server Error status and sends back a 500.html page.
        """
        builder = ResponseBuilder()
        builder.set_status("500", "Internal Server Error")
        builder.add_header("Connection", "close")
        builder.add_header("Content-Type", "text/html; charset=utf-8")
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        builder.add_header("Date", current_time)
        builder.add_header("Last-Modified", current_time)
        try:
            file_content = self.get_file_contents("500.html")
            builder.set_body(file_content)
        except IOError:
            builder.set_body("<html><body><h1>500 Internal Server Error</h1></body></html>")
        return builder.build()

def build_example_response():
    # Create a response builder instance
    response_builder = ResponseBuilder()
    # Set the status
    response_builder.set_status(200, "OK")
    # Add dynamic headers
    current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
    response_builder.add_header("Date", current_time)
    response_builder.add_header("Server", "Apache/2.4.41 (Ubuntu)")  # Example server info
    response_builder.add_header("Last-Modified", current_time)  # Assuming the resource was just modified
    response_builder.add_header("Content-Length", "1234")  # Example content length
    response_builder.add_header("Content-Type", "text/html; charset=UTF-8")
    response_builder.add_header("Connection", "keep-alive")
    # Set body (empty for HEAD request)
    response_builder.set_body(b'')
    # Build the response
    return response_builder.build()

class ResponseBuilder:
    def __init__(self):
        self.response = ''
        self.status = None
        self.headerline = ''
        self.body = b''
    
    def set_status(self, status_code, status_text):
       self.status = f"HTTP/1.1 {status_code} {status_text}"
    
    def add_header(self, key, value):
        self.headerline += f'{key}: {value}\r\n'
    
    def set_body(self, body):
        if isinstance(body, (bytes, bytearray)):
            self.body = body
        else:
            self.body = body.encode('utf-8')
    
    def build(self):
        self.response = (self.status + '\r\n' + self.headerline + '\r\n').encode('utf-8') + self.body
        return self.response

    



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Server')
    parser.add_argument('-i', '--host', default='localhost', help='Host name or IP address')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
    args = parser.parse_args()
    data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
    HTTPServer().run_server(args.host, args.port ,data_dir)