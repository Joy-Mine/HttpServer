import socket
import threading
import os
import mimetypes
import urllib.parse
import http.cookies
import argparse

parser = argparse.ArgumentParser(description='HTTP File Server')
parser.add_argument('-i', '--host', default='localhost', help='Host name or IP')
parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
args = parser.parse_args()
def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'Server listening on {host}:{port}')

    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

def handle_client(client_socket):
    # Handle client requests here
    pass

if __name__ == '__main__':
    start_server(args.host, args.port)

def handle_client(client_socket):
    request = client_socket.recv(1024).decode()
    # Parse the request, handle GET, POST, DELETE methods
    # Implement session management, file operations, etc.
    response = 'HTTP/1.1 200 OK\n\nHello World'
    client_socket.sendall(response.encode())
    client_socket.close()

def parse_http_request(request):
    # Extract method, URI, headers, and body from the request
    pass

def view_files(directory):
    # Return a list of files in the directory
    pass

def download_file(filepath):
    # Handle file downloading
    pass

def upload_file(filepath, data):
    # Handle file uploading
    pass

def delete_file(filepath):
    # Handle file deletion
    pass

def manage_sessions():
    # Generate, store, validate session IDs
    pass

def chunked_transfer_encoding(filepath):
    # Stream file data in chunks
    pass
