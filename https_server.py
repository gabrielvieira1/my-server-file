import argparse
import os
import shutil
import webbrowser
import pyzipper
import getpass
import re
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

from ssl import PROTOCOL_TLS_SERVER, SSLContext
from self_signed import SelfSignedCertificate

def is_strong_password(password):
    # Expressão regular para verificar a validade da senha
    pattern = r"^(?=.*[a-zA-Z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{8,}$"
    return re.match(pattern, password)

class CustomRequestHandler(BaseHTTPRequestHandler):
   def do_GET(self):
       if self.path == '/upload_form':
           # Carregar o formulário HTML de upload
           self.send_response(200)
           self.send_header('Content-type', 'text/html')
           self.end_headers()

           with open('upload_form.html', 'rb') as f:
               self.wfile.write(f.read())
       else:
           self.send_response(404)
           self.end_headers()

   def do_POST(self):
       if self.path == '/upload':
           content_length = int(self.headers['Content-Length'])
           post_data = self.rfile.read(content_length)
           data = parse_qs(post_data)

           # Obter o arquivo enviado pelo formulário
           file_item = data.get('file_upload')

           if file_item:
               # O campo 'file_upload' contém o arquivo enviado
               file_name = file_item[0].decode('utf-8')
               file_path = os.path.join(self.folder_encrypted_path, file_name)

               with open(file_path, 'wb') as f:
                   # Salvar o conteúdo do arquivo no diretório correto
                   f.write(self.rfile.read(int(self.headers['Content-Length'])))

               self.send_response(200)
               self.end_headers()
               self.wfile.write(b'Arquivo enviado com sucesso!')
           else:
               self.send_response(400)
               self.end_headers()
               self.wfile.write(b'Nenhum arquivo enviado!')
       else:
           self.send_response(404)
           self.end_headers()

def main(args):
    # Criar a pasta "BielFile" na pasta Documentos do usuário, caso ela não exista
    user_documents = os.path.join(os.path.expanduser("~"), "Documents")
    biel_folder_path = os.path.join(user_documents, "BielFile")
    if not os.path.exists(biel_folder_path):
        os.makedirs(biel_folder_path)

    # Criar a pasta "FolderEncrypted" dentro da pasta "BielFile" ou utilizá-la caso já exista
    folder_encrypted_path = os.path.join(biel_folder_path, "FolderEncrypted")
    if not os.path.exists(folder_encrypted_path):
        os.makedirs(folder_encrypted_path)

    # Copiar odo o conteúdo da pasta "BielFile" para a pasta "FolderEncrypted"
    for item in os.listdir(biel_folder_path):
        item_path = os.path.join(biel_folder_path, item)
        if item != "FolderEncrypted":  # Ignorar a pasta "FolderEncrypted"
            if os.path.isfile(item_path):
                destination_file = os.path.join(folder_encrypted_path, item)
                if not os.path.exists(destination_file):
                    shutil.copy(item_path, destination_file)
            elif os.path.isdir(item_path):
                destination_folder = os.path.join(folder_encrypted_path, item)
                if not os.path.exists(destination_folder):
                    shutil.move(item_path, destination_folder)

    # Solicitar que o usuário digite uma senha forte
    while True:
        password = getpass.getpass("Digite uma senha forte (mínimo de 8 caracteres, contendo letras, números e caracteres especiais): ")
        if is_strong_password(password):
            break
        else:
            print("A senha não atende aos critérios de uma senha forte.")
            print("Certifique-se de que a senha contenha pelo menos 8 caracteres, letras, números e caracteres especiais.")

    # Compactar a pasta "FolderEncrypted" com a senha aleatória
    encrypted_zip_filename = os.path.join(biel_folder_path, "FolderEncrypted_Encrypted.zip")
    with pyzipper.AESZipFile(encrypted_zip_filename, "w", compression=pyzipper.ZIP_LZMA,
                             encryption=pyzipper.WZ_AES) as zip_file:
        zip_file.setpassword(password.encode("utf-8"))
        for foldername, _, filenames in os.walk(folder_encrypted_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                arcname = os.path.relpath(file_path, folder_encrypted_path)
                zip_file.write(file_path, arcname)

    # Remover odo o conteúdo e subpastas dentro da pasta "BielFile", exceto o arquivo zipado encriptado
    for item in os.listdir(biel_folder_path):
        item_path = os.path.join(biel_folder_path, item)
        if item != "FolderEncrypted_Encrypted.zip":
            if os.path.isfile(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)

    # Imprimir a senha no console
    print("Senha para descriptografar o arquivo zipado: ", password)

    ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(SelfSignedCertificate(args.host).path)
    server = HTTPServer((args.host, args.port), BaseHTTPRequestHandler)
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    # Mude o diretório atual para a pasta "BielFile" para que o servidor sirva arquivos a partir dela
    os.chdir(biel_folder_path)

    webbrowser.open(f"https://{args.host}:{args.port}/")
    server.serve_forever()

def parse_args():
    # Obter o IP da máquina
    machine_ip = socket.gethostbyname(socket.gethostname())
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default=machine_ip)
    parser.add_argument("--port", type=int, default=4443)
    return parser.parse_args()

if __name__ == "__main__":
    main(parse_args())