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
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Thread.start(target=self.handle_request, args=(client_sock,client_address))
            Thread(target=self.handle_request, args=(client_sock,client_address)).start()
        
        #shut_down
        if self.sock is not None:
            self.sock.shutdown()
            self.sock.close()

    
    def get_content_type(file_path):
        file_extension = os.path.splitext(file_path)[1].lower()
        mime_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.gif': 'image/gif',
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
        }


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
                # if not authorization or not self.check_authorization(authorization):
                #     response=self.unauthorized_401()
                #     keep_alive=False
                #     return
                # else:
                session = headers.get('Cookie', None)
                if not session:
                    if not authorization or not self.check_authorization(authorization):
                        response=self.unauthorized_401()
                        keep_alive=False
                        return
                    username = self.get_session_username(authorization)
                    session_id = str(uuid.uuid4())
                    expiration_time = time.time() + 3600.0
                    self.sessions[session_id] = (username, expiration_time)
                    # response=self.response_with_session(session_id)
                    
                    if len(request_headline) == 3:
                        method, path, protocol = request_headline
                        if method == 'GET':
                            if headers.get('Range') is not None:
                                response=self.handle_get_range(path, headers.get('Range'), session_id)
                            else:
                                response = self.handle_get(path, session_id)
                        elif method == 'HEAD':
                            response = self.handle_head(path, session_id)
                        elif method == 'POST':
                            # request_body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''  # 这个request_body的截取方法有错误！！
                            # session_id = session.split("session-id=")[1]
                            response = self.handle_post(path, request, session_id)
                        else:
                            response=self.method_not_allowed_405({"GET","HEAD","POST"})
                            keep_alive=False
                            # 405 Method Not Allowedhandle_error(405)
                    else:
                        # response="HTTP/1.1 400 Bad Request\r\n\r\n".encode("utf-8")
                        response=self.bad_request_400()
                        keep_alive=False
                    
                    return
                if not self.check_session(session):
                    response=self.unauthorized_401()
                    keep_alive=False
                    return
                if len(request_headline) == 3:
                    method, path, protocol = request_headline
                    session_id = session.split("session-id=")[1]
                    if method == 'GET':
                        if headers.get('Range') is not None:
                            response=self.handle_get_range(path, headers.get('Range'), session_id)
                        else:
                            response = self.handle_get(path, session_id)
                    elif method == 'HEAD':
                        response = self.handle_head(path, session_id)
                    elif method == 'POST':
                        # request_body = request.split('\r\n\r\n')[1] if '\r\n\r\n' in request else ''  # 这个request_body的截取方法有错误！！
                        response = self.handle_post(path, request, session_id)
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
                print(response.decode("utf-8"))
                client_sock.sendall(response)
                client_sock.shutdown(1)
                client_sock.close()
                break
                if (not keep_alive):
                    client_sock.sendall(response)
                    client_sock.shutdown(1)
                    client_sock.close()
                    break
    
    def has_permission_other(self, file_path):
        # real_path = os.path.join(self.data_dir, file_path.strip('/'))
        file_stat = os.stat(file_path)
        return file_stat.st_mode & 0o004
    def handle_head(self, file_path, session_id):
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
            if(session_id is not None):
                builder.add_header("Set-Cookie","session-id="+session_id)
            #Set-Cookie: session-id={session_id};
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
    
    def handle_get(self, file_path, session_id):
        chunked_transfer = self.get_query_param(file_path, "chunked") == "1"
        sustech_http_value = self.get_query_param(file_path, "SUSTech-HTTP")

        file_path = file_path.split('?')[0]  # Remove the query string from the file path
        real_path = os.path.join(self.data_dir, file_path.strip('/'))

        if not os.path.exists(real_path):
            return self.not_found_404()
        elif os.path.isdir(real_path) and sustech_http_value in (None, '0'):
            return self.directory_listing(real_path, file_path, session_id)
        elif os.path.isdir(real_path) and sustech_http_value == '1':
            return self.directory_metadata(real_path, session_id)
        elif os.path.isfile(real_path) and chunked_transfer:
            return self.chunked_file_content(real_path, session_id)
        elif os.path.isfile(real_path):
            return self.file_content(real_path, session_id)
        else:
            return self.bad_request_400()
    def chunked_file_content(self, file_path, session_id):
        mime_type, _ = self.get_content_type(file_path)

        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Type": mime_type,
            "Connection": "Keep-Alive",
            "Set-Cookie": "session-id=" + session_id
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
    # def directory_listing(self, directory_path ,file_path, session_id):
    #     items = os.listdir(directory_path)
    #     if file_path!='/':
    #         file_path=file_path+'/'
    #     links = ['<a href="http://localhost:8080{1}{0}">{0}</a>'.format(item, file_path) for item in items]
    #     body = '<html><body><h1>Directory listing for {0}</h1><ul>{1}</ul></body></html>'.format(
    #         directory_path, ''.join(f'<li>{link}</li>' for link in links))
    #     return self.build_response("200", "OK", "text/html; charset=UTF-8", body, session_id)
    def directory_listing(self, directory_path, file_path, session_id):
        items = os.listdir(directory_path)
        links = []
        for item in items:
            item_path = os.path.join(directory_path, item)
            display_name = item + '/' if os.path.isdir(item_path) else item
            link = '<li><a href="{0}">{1}</a></li>'.format(item, display_name)
            links.append(link)
        body = ('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">'
                '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
                '<title>Directory listing for {0}</title></head>'
                '<body><h1>Directory listing for {0}</h1><hr><ul>{1}</ul><hr></body></html>').format(
                file_path, ''.join(links))
        return self.build_response("200", "OK", "text/html; charset=UTF-8", body, session_id)
    # def directory_metadata(self, directory_path, session_id):
    #     items = os.listdir(directory_path)
    #     body = json.dumps(items)
    #     return self.build_response("200", "OK", "application/json", body, session_id)
    def directory_metadata(self, directory_path, session_id):
        items = os.listdir(directory_path)
        formatted_items = []
        for item in items:
            full_path = os.path.join(directory_path, item)
            if os.path.isdir(full_path):
                formatted_items.append(item + "/")
            elif os.path.isfile(full_path):
                formatted_items.append(item)
        body = json.dumps(formatted_items)
        return self.build_response("200", "OK", "application/json", body, session_id)
    def file_content(self, file_path, session_id):
        mime_type, _ = self.get_content_type(file_path)
        with open(file_path, 'rb') as file:
            body = file.read()
        body=body.decode('utf-8')
        return self.build_response("200", "OK", mime_type, body, session_id)
        # response = f'HTTP/1.1 200 OK\r\nContent-Type: {mime_type}\r\nContent-Length: {len(body)}\r\n\r\n'
        # response = response.encode('utf-8') + body
        return response
    def build_response(self, status_code, status_text, content_type, body, session_id):
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "Keep-Alive",
            "Set-Cookie": "session-id=" + session_id
        }
        response_line = "HTTP/1.1 {0} {1}\r\n".format(status_code, status_text)
        header_lines = "\r\n".join("{0}: {1}".format(k, v) for k, v in headers.items())
        return "{0}{1}\r\n\r\n{2}".format(response_line, header_lines, body).encode('utf-8')

    def handle_post(self, path, request, session_id):
        # 分割路径和查询参数
        path_parts = path.split('?')
        base_path = path_parts[0] if path_parts else path

        # 根据基本路径决定调用哪个方法
        if base_path == '/upload':
            return self.handle_upload(path, request, session_id)
        elif base_path == '/delete':
            return self.handle_delete(path, session_id)
        else:
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "keep-alive")
            builder.add_header("Set-Cookie","session-id="+session_id)
            # builder.add_header("Content-Type", self.get_file_mime_type(real_path.split(".")[1]))
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            return builder.build()

    def handle_upload(self, path, request, session_id):
        username = self.sessions[session_id][0]
        target_path = self.get_query_param(path, 'path')
        if not target_path or not target_path.startswith(f"{username}/"):
            return self.forbidden_403()
        real_path = os.path.join(self.data_dir, target_path.strip('/'))
        if not os.path.exists(os.path.dirname(real_path)):
            return self.not_found_404()
        # 寻找分隔符
        boundary_match = re.search(r'boundary=([^\s]+)', request)
        if not boundary_match:
            return self.bad_request_400()
        boundary = boundary_match.group(1).strip()
        # 寻找文件名
        filename_match = re.search(r'filename="([^"]+)"', request)
        if filename_match:
            filename = filename_match.group(1)
        else:
            return self.bad_request_400()
        real_path = os.path.join(real_path, filename)
        # 提取文件内容
        pattern = r'Content-Type: .+\r\n\r\n(.+?)\r\n--' + re.escape(boundary)
        file_content_match = re.search(pattern, request, re.DOTALL)
        if not file_content_match:
            return self.bad_request_400()
        file_data = file_content_match.group(1)
        # 保存文件
        with open(real_path, 'wb') as file:
            file.write(file_data.encode('utf-8'))
        return self.build_response("200", "OK", "text/html; charset=UTF-8", "File uploaded successfully.", session_id)

    def handle_delete(self, path, session_id):
        # 提取请求路径中的文件路径
        query_param = path.split("?path=")
        if len(query_param) < 2:
            return self.bad_request_400()  # 无效请求，没有提供路径参数
        file_path = query_param[1]
        # 获取会话中的用户名
        session_name = self.sessions[session_id][0]
        # 构建完整的文件路径
        user_dir = os.path.join(self.data_dir, session_name)
        full_path = os.path.join(self.data_dir, file_path.strip("/"))
        # 检查用户是否有权限
        if not full_path.startswith(user_dir):
            return self.forbidden_403()
        # 检查文件是否存在
        if not os.path.exists(full_path):
            return self.not_found_404()
        try:
            # 删除文件
            os.remove(full_path)
            builder = ResponseBuilder()
            builder.set_status("200", "OK")
            builder.add_header("Connection", "Keep-Alive")
            builder.add_header("Content-Type", "text/html; charset=UTF-8")
            builder.add_header("Set-Cookie","session-id="+session_id)
            builder.set_body("File deleted successfully.")
            return builder.build()
        except Exception as e:
            print(f"Exception in handle_delete: {e}")
            return self.server_error_500()

    

    def handle_get_range(self, file_path, range_header, session_id):
        real_path = os.path.join(self.data_dir, file_path.strip('/'))
        if not os.path.exists(real_path) or os.path.isdir(real_path):
            return self.not_found_404()

        file_size = os.path.getsize(real_path)
        ranges = self.parse_ranges(range_header, file_size)

        if not ranges:
            return self.range_not_satisfiable_416(file_size)

        if len(ranges) == 1:
            return self.single_range_response(real_path, ranges[0], file_size, session_id)
        else:
            return self.multiple_ranges_response(real_path, ranges, file_size, session_id)
    def parse_ranges(self, range_header, file_size):
        ranges = []
        # 移除可能存在的 "bytes=" 前缀
        if 'bytes=' in range_header:
            range_header = range_header.split('bytes=')[1]
        range_strings = range_header.split(",")
        for range_string in range_strings:
            try:
                start_end = range_string.split("-")
                if len(start_end) != 2:
                    continue
                start = int(start_end[0]) if start_end[0] else 0
                end = int(start_end[1]) if start_end[1] else file_size - 1
                # 检查范围的有效性
                if 0 <= start <= end < file_size:
                    ranges.append((start, end))
            except ValueError:
                continue
        return ranges if ranges else None
    def single_range_response(self, file_path, range_tuple, file_size, session_id):
        start, end = range_tuple
        length = end - start + 1
        mime_type, _ = self.get_content_type(file_path)
        headers = {
            "Content-Type": mime_type,
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(length),
            "Connection": "Keep-Alive",
            "Set-Cookie": "session-id=" + session_id
        }
        response_line = "HTTP/1.1 206 Partial Content\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        
        with open(file_path, 'rb') as file:
            file.seek(start)
            body = file.read(length)
        
        response = f"{response_line}{header_lines}\r\n\r\n".encode() + body
        return response
    def multiple_ranges_response(self, file_path, ranges, file_size, session_id):
        boundary = "THISISMYSELFDIFINEDBOUNDARY"
        mime_type, _ = self.get_content_type(file_path)
        headers = {
            "Content-Type": f"multipart/byteranges; boundary={boundary}",
            "Connection": "Keep-Alive",
            "Set-Cookie": "session-id=" + session_id
        }
        response_line = "HTTP/1.1 206 Partial Content\r\n"
        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())

        body = b""
        for start, end in ranges:
            length = end - start + 1
            body += f"--{boundary}\r\n".encode()
            body += f"Content-Type: {mime_type}\r\n".encode()
            body += f"Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n".encode()
            # todo：不确定有没有这个“bytes”
            
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
        response_headers = f'HTTP/1.1 200 OK\r\nSet-Cookie: session-id={session_id};\r\nConnection: close\r\n\r\n'
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