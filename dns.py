import socket
import threading

class DNSProxyServer:
    def __init__(self, config_file):
        self.blacklist = set()
        self.upstream_server = ("8.8.8.8", 53)
        self.load_config(config_file)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("127.0.0.1", 53))
        
    def load_config(self, config_file):
        with open(config_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line.startswith("blacklist"):
                    _, domain = line.split()
                    self.blacklist.add(domain)
                elif line.startswith("upstream_server"):
                    _, ip, port = line.split()
                    self.upstream_server = (ip, int(port))

    def is_blacklisted(self, domain):
        return domain in self.blacklist

    def resolve_dns(self, query_data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(query_data, self.upstream_server)
            response_data, _ = client_socket.recvfrom(1024)
        return response_data

    def handle_request(self, data, client_address):
        try:
            domain = self.extract_domain(data)
            print(domain)
            if self.is_blacklisted(domain):
                response_data = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:]
            else:
                response_data = self.resolve_dns(data)
            self.server_socket.sendto(response_data, client_address)
        except Exception as e:
            print("Error handling request:", str(e))

    def extract_domain(self, data):
        domain = ""
        index = 12  # Start of the domain name in DNS query
        length = data[index]
        while length != 0:
            domain += data[index + 1:index + 1 + length].decode("utf-8") + "."
            index += length + 1
            length = data[index]
        domain = domain[:-1]
        return domain

    def start(self):
        print("DNS Proxy Server started.")
        while True:
            data, client_address = self.server_socket.recvfrom(1024)
            threading.Thread(target=self.handle_request, args=(data, client_address)).start()

if __name__ == "__main__":
    proxy_server = DNSProxyServer("config.txt")
    proxy_server.start()
