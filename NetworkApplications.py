#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer 


    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        start = time.time()
        icmpSocket.settimeout(timeout)
        try:
            data, address = icmpSocket.recvfrom(1024)
            end = time.time()
            delay = end - start
            icmpHeader = data[20:28]                                                       # Unpack the packet header for useful information
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmpHeader)
            if packet_ID == ID:                                                            # Check that the ID matches between the request and reply
                 return delay 
            else:
                 print("wrong packet id")
                 return None
        except socket.timeout:
            return None                                                                    # Handle a timeout
        
    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        header = struct.pack("bbHHh", 8, 0, 0, ID, 1)
        payload = b"abcdefghijklmnopqrstuvwxyz"
        packet = header + payload
        myChecksum = self.checksum(packet)                                                 # Compute the checksum
        header = struct.pack("bbHHh", 8, 0, myChecksum, ID, 1)
        packet = header + payload
        ttl = struct.pack('I', 64)                                                         # Send the packet
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        icmpSocket.sendto(packet, (destinationAddress, 1))
        packetSize = len(packet)                                                           # Return the size of the packet and the TTL used
        ttlUsed = struct.unpack('I', ttl)[0]
        return packetSize, ttlUsed

    def doOnePing(self, destinationAddress, timeout):
        icmp = socket.getprotobyname("icmp")                                               # Create ICMP socket
        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as errorCode:
            if errorCode.errno == 1:                                                       # Operation not permitted - Add more information to the error message
                raise socket.error("ICMP messages can only be sent from processes running as root.(Sudo)")
            raise
        packetSize, ttlUsed = self.sendOnePing(icmpSocket, destinationAddress, 1)           # Call sendOnePing function
        delay = self.receiveOnePing(icmpSocket, destinationAddress, 1, timeout)             # Call receiveOnePing function
        icmpSocket.close()                                                                  # Close ICMP socket
        return delay, packetSize, ttlUsed                                                   # Return total network delay, packet size and TTL used

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        destinationAddress = socket.gethostbyname(args.hostname)
        timeout = args.timeout
        while True:                                                                         # Call doOnePing function, approximately every second
            delay, packetSize, ttlUsed = self.doOnePing(destinationAddress, timeout)
            if delay is not None:                                                           # Print out the returned delay (and other relevant details) using the printOneResult method
                self.printOneResult(destinationAddress, packetSize, delay * 1000, ttlUsed)
            time.sleep(1)                                                                   # Continue this process until stopped

class Traceroute(NetworkApplication):
    def receiveOnePing(self, icmpSocket, timeout, ttl):
        start = time.time()
        icmpSocket.settimeout(timeout)
        try:
            data, address = icmpSocket.recvfrom(1024)
            end = time.time()
            delay = end - start
            icmpHeader = data[20:28]                                                       # Unpack the packet header for useful information
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmpHeader)
            if packet_ID == self.ID and sequence == ttl:                                   # Checks that the ID and sequence number match between the request sent and  the reply
                return delay, address[0]
        except socket.timeout:
            return None, None                                                              # Try and Catch used for timeouts
        return delay, address[0]                                                           # Return the delay and address even if packet_ID and sequence number do not match

    def sendOnePing(self, icmpSocket, dest_addr, ttl):
        header = struct.pack("bbHHh", 8, 0, 0, self.ID, 1)
        payload = b"abcdefghijklmnopqrstuvwxyz"
        packet = header + payload
        ttl = struct.pack('I', ttl)                                                        # Set the TTL
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        myChecksum = self.checksum(packet)                                                 # Compute the checksum
        header = struct.pack("bbHHh", 8, 0, myChecksum, self.ID, 1)
        packet = header + payload                                                          # Send the packet
        icmpSocket.sendto(packet, (dest_addr, 1))
        packetSize = len(packet)                                                           # Return the size of the packet and the TTL used
        ttlUsed = struct.unpack('I', ttl)[0]
        return packetSize, ttlUsed

    def doOneTrace(self, dest_name, timeout, ttl):
        dest_addr = socket.gethostbyname(dest_name)
        icmp = socket.getprotobyname("icmp")                                               # Create ICMP socket
        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as errorCode:
            if errorCode.errno == 1:
                raise socket.error("ICMP messages can only be sent from processes running as root.(Use Sudo)")  # Lets the user know to run in admin privaleges
            raise

        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))      # Set the TTL for the socket
        packetSize, ttlUsed = self.sendOnePing(icmpSocket, dest_addr, ttl)                  # Call sendOnePing function
        delay, address = self.receiveOnePing(icmpSocket, timeout, ttl)                      # Call receiveOnePing function
        icmpSocket.close()
        done = address == dest_addr                                                         # Check if the received packet has the same IP address as the destination

        return delay, address, packetSize, ttlUsed, done                                    # Return the results

    def __init__(self, args):
        print(f'Traceroute to: {args.hostname}...')
        self.ID = random.randint(0, 65535)
        max_ttl = 30
        timeout = args.timeout
        delays = []
        for ttl in range(1, max_ttl + 1):                                                   # Perform traceroute for each TTL value
            print(f'{ttl}\t', end='', flush=True)
            addresses = []
            for i in range(3):                                                              # Perform three probes for each TTL value
                delay, address, packetSize, ttlUsed, done = self.doOneTrace(args.hostname, timeout, ttl)
                if delay is not None:
                    addresses.append(delay*1000)
            if addresses:
                self.printMultipleResults(ttl, address, addresses)
                delays.extend(addresses)
            if done:
                break
        packetLoss = (1 - (len(delays) / (max_ttl * 3))) * 100 if max_ttl * 3 > 0 else 0.0
        minimumDelay = min(delays) if delays else 0.0
        averageDelay = sum(delays) / len(delays) if delays else 0.0
        maximumDelay = max(delays) if delays else 0.0
        self.printAdditionalDetails(packetLoss, minimumDelay, averageDelay, maximumDelay)           

class ParisTraceroute(NetworkApplication):
    def receiveOnePing(self, icmpSocket, timeout, ttl):
        start = time.time()
        icmpSocket.settimeout(timeout)
        try:
            data, address = icmpSocket.recvfrom(1024)
            end = time.time()
            delay = end - start
            icmpHeader = data[20:28]                                                       # Unpack the packet header for useful information
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmpHeader)
            if packet_ID == self.ID and sequence == ttl:                                   # Checks that the ID and sequence number match between the request sent and  the reply
                return delay, address[0]
        except socket.timeout:
            return None, None                                                              # Try and Catch used for timeouts
        return delay, address[0]                                                           # Return the delay and address even if packet_ID and sequence number do not match

    def sendOnePing(self, icmpSocket, dest_addr, ttl):
        ttl = struct.pack('I', ttl)                                                        # Set the TTL
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        packet= self.makepacket()                                                          
        icmpSocket.sendto(packet, (dest_addr, 1))                                          # Send the packet
        ttlUsed = struct.unpack('I', ttl)[0]
        return ttlUsed                                                                     # Returns TTL used

    def doOneTrace(self, dest_name, timeout, ttl):
        dest_addr = socket.gethostbyname(dest_name)
        icmp = socket.getprotobyname("icmp")                                               # Create ICMP socket
        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as errorCode:
            if errorCode.errno == 1:
                raise socket.error("ICMP messages can only be sent from processes running as root.(Use Sudo)")  # Lets the user know to run in admin privaleges
            raise

        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))      # Set the TTL for the socket
        ttlUsed = self.sendOnePing(icmpSocket, dest_addr, ttl)                              # Call sendOnePing function
        delay, address = self.receiveOnePing(icmpSocket, timeout, ttl)                      # Call receiveOnePing function
        icmpSocket.close()
        
        done = address == dest_addr                                                         # Check if the received packet has the same IP address as the destination

        return delay, address, ttlUsed, done                                                # Return the results

    def makepacket(self):
        header = struct.pack("bbHHh", 8, 0, 0, self.ID, 1)
        payload = b"abcdefghijklmnopqrstuvwxyz"
        packet = header + payload
        myChecksum = self.checksum(packet)                                                 # Compute the checksum
        header = struct.pack("bbHHh", 8, 0, myChecksum, self.ID, 1)
        packet = header + payload
        return packet

    def __init__(self, args):
        print(f'Traceroute to: {args.hostname}...')
        self.ID = random.randint(0, 65535)
        max_ttl = 30
        timeout = args.timeout
        delays = []
        for ttl in range(1, max_ttl + 1):                                                   # Perform traceroute for each TTL value
            print(f'{ttl}\t', end='', flush=True)
            addresses = []
            for i in range(3):                                                              # Perform three probes for each TTL value
                delay, address, ttlUsed, done = self.doOneTrace(args.hostname, timeout, ttl)
                if delay is not None:
                    addresses.append(delay*1000)
            if addresses:
                self.printMultipleResults(ttl, address, addresses)
                delays.extend(addresses)
            if done:
                break
        packetLoss = (1 - (len(delays) / (max_ttl * 3))) * 100 if max_ttl * 3 > 0 else 0.0
        minimumDelay = min(delays) if delays else 0.0
        averageDelay = sum(delays) / len(delays) if delays else 0.0
        maximumDelay = max(delays) if delays else 0.0
        self.printAdditionalDetails(packetLoss, minimumDelay, averageDelay, maximumDelay)
    


class WebServer(NetworkApplication):
    
    def handleRequest(self, tcpSocket):
        request = tcpSocket.recv(1024).decode('utf-8')
        path = request.split(' ')[1]
        
        try:
            with open(path[1:], 'rb') as file:
                content = file.read()
                response = 'HTTP/1.1 200 OK\r\n\r\n' + content.decode('utf-8')
        except:
            response = 'HTTP/1.1 404 Not Found\r\n\r\nFile Not Found'
        
        tcpSocket.sendall(response.encode('utf-8'))
        tcpSocket.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', args.port))
        serverSocket.listen(1)

        try:
            while True:
                connSocket, addr = serverSocket.accept()
                self.handleRequest(connSocket)  # pass connSocket as second argument
        finally:
            serverSocket.close()

class Proxy(NetworkApplication):
    
    def __init__(self, args):
        self.cache_dir = 'cache'
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.server_address = ('', args.port)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(1)
        print('Starting proxy server on port %d' % args.port)
        self.start()



    def handle_client(self, client_socket):
        print('Handling client request')
        request = client_socket.recv(1024).decode('utf-8')
        if not request:
            return
        print('Request received:')
        print(request)
        hostname = request.split('Host: ')[-1].split('\r\n')[0]                      # Extract hostname from client request
        print(hostname)
        if not hostname:
            print('Could not parse hostname from request')
            return
        self.web_server_address = (hostname, 80)                                     # Update web server address to use parsed hostname
        web_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # Forward request to web server
        web_server_socket.connect(self.web_server_address)
        web_server_socket.sendall(request.encode('utf-8'))

        cache_key = (request + hostname).encode('utf-8')
        cache_file = os.path.join(self.cache_dir, str(abs(hash(cache_key))))
        if os.path.exists(cache_file):                                              # Check cache for response
            print('Serving response from cache')
            with open(cache_file, 'rb') as f:
                response = f.read()
        else:
            response = web_server_socket.recv(8192)                                 # Read response from web server
            print('Received response from web server:')
            with open(cache_file, 'wb') as f:
                    f.write(response)
                    print('Storing response in cache')
            web_server_socket.close()                                               # Close web server socket

        client_socket.sendall(response)                                             # Send response to client
        client_socket.close()
        
    def start(self):
        print('Proxy server started.')
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            print('Proxy server stopped')
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
