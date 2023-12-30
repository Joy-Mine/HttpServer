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
import json
import re


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
        while True:
            try:
                print(f"Accept request from {client_address}")
                response=None
                request = client_sock.recv(4096).decode('utf-8')
                print("request:")
                print(request)
                
                request_lines = request.strip().split('\r\n')
                request_headline = request_lines[0].split()

                headers = {}
                for line in request_lines[1:]:
                    if not line:
                        break
                    key, value = line.split(': ', 1)
                    headers[key] = value
                
                keep_alive=True
                authorization = headers.get('Authorization', None)
                if not authorization or not self.check_authorization(authorization):
                    response=self.unauthorized_401()
                    keep_alive=False
                    return
                else:
                    session = headers.get('Cookie', None)
                    if not session:
                        username = self.get_session_username(authorization)
                        session_id = str(uuid.uuid4())
                        expiration_time = time.time() + 3600.0
                        self.sessions[session_id] = (username, expiration_time)
                        response=self.response_with_session(session_id)
                        return
                    if not self.check_session(session):
                        response=self.unauthorized_401()
                        keep_alive=False
                        return
                    if len(request_headline) == 3:
                        method, path, protocol = request_headline
                        if method == 'GET':
                            if headers.get('Range') is not None:
                                response=self.handle_get_range(path)
                            else:
                                response = self.handle_get(path)
                        elif method == 'HEAD':
                            response = self.handle_head(path)
                        elif method == 'POST':
                            request_body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''
                            response = self.handle_post(path, request_body, session)
                        else:
                            response=self.method_not_allowed_405({"GET","HEAD","POST"})
                            keep_alive=False
                            # 405 Method Not Allowedhandle_error(405)
                    else:
                        # response="HTTP/1.1 400 Bad Request\r\n\r\n".encode("utf-8")
                        response=self.bad_request_400()
                        keep_alive=False
                
            except Exception as e:
                print(f"Exception in handling request: {e}")
                # response = "HTTP/1.1 500 Internal Server Error\r\n\r\n".encode("utf-8")
                response=self.server_error_500()
                keep_alive=False
            finally:
                print("response:")
                # todo:演示时屏蔽此行
                print(response.decode("utf-8"))
                client_sock.sendall(response)
                if (not keep_alive):
                    client_sock.shutdown(1)
                    client_sock.close()
                    break
    
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
            builder.add_header("Connection", "keep-alive")
            # builder.add_header("Content-Type", self.get_file_mime_type(real_path.split(".")[1]))
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            return builder.build()
    

    def get_query_param(self, url, param_name):
        # Example usage:
        # url = '/11912113/?SUSTech-HTTP=1'
        # param_value = self.get_query_param(url, 'SUSTech-HTTP')
        # print(param_value)  # Output should be '1'
        query_string_start = url.find('?')
        if query_string_start == -1:
            return None
        query_string = url[query_string_start + 1:]
        params = query_string.split('&')
        for param in params:
            key_value = param.split('=')
            if len(key_value) == 2:
                key, value = key_value
                if key == param_name:
                    return value
        return None
    
    def handle_get(self, file_path):
        chunked_transfer = self.get_query_param(file_path, "chunked") == "1"
        sustech_http_value = self.get_query_param(file_path, "SUSTech-HTTP")

        file_path = file_path.split('?')[0]  # Remove the query string from the file path
        real_path = os.path.join(self.data_dir, file_path.strip('/'))

        if not os.path.exists(real_path):
            return self.not_found_404()
        elif os.path.isdir(real_path) and sustech_http_value in (None, '0'):
            return self.directory_listing(real_path)
        elif os.path.isdir(real_path) and sustech_http_value == '1':
            return self.directory_metadata(real_path)
        elif os.path.isfile(real_path) and chunked_transfer:
            return self.chunked_file_content(real_path)
        elif os.path.isfile(real_path):
            return self.file_content(real_path)
        else:
            return self.bad_request_400()
    def chunked_file_content(self, file_path):
        mime_type, _ = mimetypes.guess_type(file_path)
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Type": mime_type,
            "Connection": "Keep-Alive"
        }
        response_line = "HTTP/1.1 200 OK\r\n"
        header_lines = "\r\n".join("{0}: {1}".format(k, v) for k, v in headers.items())

        response = "{0}{1}\r\n\r\n".format(response_line, header_lines).encode('utf-8')
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(4096)  # Read file in chunks of 4KB
                if not chunk:
                    break
                response += f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n"
        response += b"0\r\n\r\n"  # End of chunked transfer
        return response
    def directory_listing(self, directory_path):
        items = os.listdir(directory_path)
        links = ['<a href="/{0}">{0}</a>'.format(item) for item in items]
        body = '<html><body><h1>Directory listing for {0}</h1><ul>{1}</ul></body></html>'.format(
            directory_path, ''.join(f'<li>{link}</li>' for link in links))
        return self.build_response("200", "OK", "text/html; charset=UTF-8", body)
    def directory_metadata(self, directory_path):
        items = os.listdir(directory_path)
        body = json.dumps(items)
        return self.build_response("200", "OK", "application/json", body)
    def file_content(self, file_path):
        mime_type, _ = mimetypes.guess_type(file_path)
        with open(file_path, 'rb') as file:
            body = file.read()
        return self.build_response("200", "OK", mime_type, body)
    def build_response(self, status_code, status_text, content_type, body):
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "Keep-Alive"
        }
        response_line = "HTTP/1.1 {0} {1}\r\n".format(status_code, status_text)
        header_lines = "\r\n".join("{0}: {1}".format(k, v) for k, v in headers.items())
        return "{0}{1}\r\n\r\n{2}".format(response_line, header_lines, body).encode('utf-8')

    def handle_post(self, path, request_body, session):
        if '/upload' in path:
            return self.handle_upload(path, request_body, session)
        elif '/delete' in path:
            return self.handle_delete(path, session)
        else:
            return self.bad_request_400()
        
    def handle_upload(self, path, request_body, session):
        username = self.sessions[session][0]

        target_path = self.get_query_param(path, 'path')

        if not target_path or not target_path.startswith(f"/{username}/"):
            return self.forbidden_403()

        real_path = os.path.join(self.data_dir, target_path.strip('/'))
        if not os.path.exists(os.path.dirname(real_path)):
            return self.not_found_404()

        with open(real_path, 'wb') as file:
            file.write(request_body.encode('utf-8'))

        return self.build_response("200", "OK", "text/html; charset=UTF-8", "File uploaded successfully.")
    
    def handle_delete(self, path, session):
        username = self.sessions[session][0]

        target_path = self.get_query_param(path, 'path')

        if not target_path or not target_path.startswith(f"/{username}/"):
            return self.forbidden_403()

        real_path = os.path.join(self.data_dir, target_path.strip('/'))
        if not os.path.exists(real_path):
            return self.not_found_404()

        os.remove(real_path)

        return self.build_response("200", "OK", "text/html; charset=UTF-8", "File deleted successfully.")



    # def handle_post(self, path, request_body, session):
    #     try:
    #         if (not os.path.exists(path)):
    #             return self.not_found_404()
    #         elif(not self.has_permission_other(path)):
    #             return self.forbidden_403()
    #         else:
    #             post_type = path.split("?")[0]
    #             post_path = path.split("?")[1]
    #             if post_type == "/upload":
    #                 return self.handle_upload(post_path, request_body,session)
    #             elif post_type == "/delete":
    #                 return self.handle_delete(post_path, session)
    #             else:
    #                 return self.bad_request_400()
    #                 # 400 Bad Request
    #     except Exception as e:
    #         print(f"Exception in handle_post: {e}")
    #         return self.server_error_500()
    # def handle_upload(self, post_path, request_body,session): 
    #     # 构建用户专用目录
    #     temp = post_path.split("=")[1]
    #     user_dir = os.path.join("data/", temp)
    #     user_name = post_path.split("/")[1]

    #     session_name = self.sessions[session][0]
    #     if session_name != user_name:
    #         return self.forbidden_403()
    #     if not os.path.exists(user_dir):
    #         return self.not_found_404()
        
    #     # 接受文件并获取文件名
    #     # 以行为单位分割request_body
    #     file_body = request_body.split("\r\n\r\n")
    #     part1 = file_body[1]
    #     part2 = file_body[2]
    #     # 以boundary为分割符分割part1
    #     name_line = part1.split("\r\n")[1]
    #     file_content = part2.split("\r\n")[0]
    #     # 获取文件名
    #     file_name_index = name_line.find("filename=")
    #     file_name_start = file_name_index+10
    #     file_name_end = name_line.find('"', file_name_start)
    #     file_name = name_line[file_name_start:file_name_end]
    #     if file_name_index == -1:
    #         return self.bad_request_400()
    #     else:
    #         file_name_start = file_name_index+10
    #         file_name_end = name_line.find('"', file_name_start)
    #         file_name = name_line[file_name_start:file_name_end]
    #     final_path = os.path.join(user_dir, file_name)
    #     with open(final_path, 'wb') as file:
    #         file.write(file_content.encode("utf-8"))
    #     # 200 OK
    #     builder = ResponseBuilder()
    #     builder.set_status("200", "OK")
    #     builder.add_header("Connection", "Keep-Alive")
    #     builder.add_header("Content-Type", "text/plain; charset=UTF-8")
    #     return builder.build()
    # def handle_delete(self, file_path,session):
    #     # 构建用户专用目录
    #     temp = file_path.split("=")[1]
    #     user_dir = os.path.join("data/", temp)
    #     user_name = file_path.split("")[1]
    #     session_name = self.sessions[session][0]
    #     if session_name != user_name:
    #         return self.forbidden_403()
    #     if not os.path.exists(user_dir):
    #         return self.not_found_404()
    #     try:
    #         os.remove(user_dir)
    #         builder = ResponseBuilder()
    #         builder.set_status("200", "OK")
    #         builder.add_header("Connection", "Keep-Alive")
    #         builder.add_header("Content-Type", "text/html; charset=UTF-8")
    #         builder.set_body(file_path)
    #         return builder.build()
    #     except Exception as e:
    #         print(f"Exception in handle_delete: {e}")
    #         return self.server_error_500()
    

    def handle_get_range(self, file_path, range_header):
        real_path = os.path.join(self.data_dir, file_path.strip('/'))
        if not os.path.exists(real_path) or os.path.isdir(real_path):
            return self.not_found_404()

        file_size = os.path.getsize(real_path)
        ranges = self.parse_ranges(range_header, file_size)

        if not ranges:
            return self.range_not_satisfiable_416(file_size)

        if len(ranges) == 1:
            return self.single_range_response(real_path, ranges[0], file_size)
        else:
            return self.multiple_ranges_response(real_path, ranges, file_size)
    def parse_ranges(self, range_header, file_size):
        ranges = []
        range_pattern = re.compile(r"bytes=(\d*)-(\d*)")

        for part in range_header.split(","):
            match = range_pattern.match(part)
            if match:
                start, end = match.groups()
                start = int(start) if start else 0
                end = int(end) if end else file_size - 1

                if start > end or end >= file_size:
                    return None  # Invalid range
                ranges.append((start, end))
        
        return ranges
    def single_range_response(self, file_path, range_tuple, file_size):
        start, end = range_tuple
        length = end - start + 1
        mime_type, _ = mimetypes.guess_type(file_path)
        headers = {
            "Content-Type": mime_type,
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(length),
            "Connection": "Keep-Alive"
        }
        response_line = "HTTP/1.1 206 Partial Content\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        
        with open(file_path, 'rb') as file:
            file.seek(start)
            body = file.read(length)
        
        response = f"{response_line}{header_lines}\r\n\r\n".encode() + body
        return response
    def multiple_ranges_response(self, file_path, ranges, file_size):
        boundary = "3d6b6a416f9b5"
        mime_type, _ = mimetypes.guess_type(file_path)
        headers = {
            "Content-Type": f"multipart/byteranges; boundary={boundary}",
            "Connection": "Keep-Alive"
        }
        response_line = "HTTP/1.1 206 Partial Content\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())

        body = b""
        for start, end in ranges:
            length = end - start + 1
            body += f"--{boundary}\r\n".encode()
            body += f"Content-Type: {mime_type}\r\n".encode()
            body += f"Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n".encode()
            
            with open(file_path, 'rb') as file:
                file.seek(start)
                body += file.read(length) + b"\r\n"

        body += f"--{boundary}--\r\n".encode()

        response = f"{response_line}{header_lines}\r\n\r\n".encode() + body
        return response
    def range_not_satisfiable_416(self, file_size):
        response_line = "HTTP/1.1 416 Range Not Satisfiable\r\n"
        headers = {
            "Content-Range": f"bytes */{file_size}",
            "Connection": "close"
        }
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        response = f"{response_line}{header_lines}\r\n\r\n"
        return response.encode()
        
    def check_session(self, session):
        try:
            session_id = session.split("session-id=")[1]
            # Check if the session cookie is valid and not expired
            if session_id in self.sessions:
                _, expiration_time = self.sessions[session_id]
                result = expiration_time > time.time()
                return result
            else:
                return None
        except Exception as e:
            print(f"Exception in check_session{e}")
        finally:
            return None
    def check_user_right(self, session_cookie, user):
        session_name = self.sessions[session_cookie][0]
        print(f'sessionname is {session_name},   user is {user}')
        if session_name != user:
            return False
        else:
            return True
    def get_session_username(self, auth_header):
        _, encoded_info = auth_header.split(' ')
        decoded_info = base64.b64decode(encoded_info).decode('utf-8')
        username, _ = decoded_info.split(':', 1)
        return username
    def check_authorization(self, authorization):
        credentials = {'client1': '123', 
                       'client2': '123', 
                       'client3': '123'}
        try:
            scheme, encoded_info = authorization.split(' ')
            if scheme != "Basic":
                print("暂不支持其它认证方案")
                return False
            decoded_info = base64.b64decode(encoded_info).decode('utf-8')
            username, password = decoded_info.split(":")
            return credentials.get(username) == password
        except (ValueError, IndexError, base64.binascii.Error):
            # 处理各种潜在异常
            return False
    
    def response_with_session(self, session_id):
        response_headers = f'HTTP/1.1 200 OK\r\nSet-Cookie: session-id={session_id};\r\n\r\n'
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

    def example_response():
        response_builder = ResponseBuilder()
        response_builder.set_status(200, "OK")
        
        current_time = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")
        response_builder.add_header("Date", current_time)
        response_builder.add_header("Server", "Apache/2.4.41 (Ubuntu)")  # Example server info
        response_builder.add_header("Last-Modified", current_time)  # Assuming the resource was just modified
        response_builder.add_header("Content-Length", "1234")  # Example content length
        response_builder.add_header("Content-Type", "text/html; charset=UTF-8")
        response_builder.add_header("Connection", "keep-alive")
        
        response_builder.set_body(b'')
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