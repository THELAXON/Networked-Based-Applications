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
        start_time = time.time()
        icmpSocket.settimeout(timeout)
        
        try:
            data, address = icmpSocket.recvfrom(1024)

            end_time = time.time()
            delay = end_time - start_time
            
            # Unpack the packet header for useful information
            icmpHeader = data[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmpHeader)
            
            # Check that the ID matches between the request and reply
            if packet_ID == ID:
                 return delay 
            else:
                 print("wrong packet id")
                 return None
        except socket.timeout:
            # Handle a timeout
            return None
    
    

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        header = struct.pack("bbHHh", 8, 0, 0, ID, 1)
        payload = b"abcdefghijklmnopqrstuvwxyz"
        packet = header + payload

        # Compute the checksum
        myChecksum = self.checksum(packet)
        header = struct.pack("bbHHh", 8, 0, myChecksum, ID, 1)
        packet = header + payload

        # Send the packet
        ttl = struct.pack('I', 64)
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        icmpSocket.sendto(packet, (destinationAddress, 1))

        # Return the size of the packet and the TTL used
        packetSize = len(packet)
        ttlUsed = struct.unpack('I', ttl)[0]
        return packetSize, ttlUsed


    def doOnePing(self, destinationAddress, timeout):
        # Create ICMP socket
        icmp = socket.getprotobyname("icmp")
        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as errorCode:
            if errorCode.errno == 1:
                # Operation not permitted - Add more information to the error message
                raise socket.error("ICMP messages can only be sent from processes running as root.")
            raise
        # Call sendOnePing function

        packetSize, ttlUsed = self.sendOnePing(icmpSocket, destinationAddress, 1)

        # Call receiveOnePing function
        delay = self.receiveOnePing(icmpSocket, destinationAddress, 1, timeout)

        # Close ICMP socket
        icmpSocket.close()

        # Return total network delay, packet size and TTL used
        return delay, packetSize, ttlUsed


    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        destinationAddress = socket.gethostbyname(args.hostname)
        timeout = args.timeout

        # Call doOnePing function, approximately every second
        while True:
            delay, packetSize, ttlUsed = self.doOnePing(destinationAddress, timeout)

            # Print out the returned delay (and other relevant details) using the printOneResult method
            if delay is not None:
                self.printOneResult(destinationAddress, packetSize, delay * 1000, ttlUsed)

            # Continue this process until stopped
            time.sleep(1)
            
class Traceroute(NetworkApplication):

    def receiveOnePing(self, icmpSocket, timeout, ttl):
        start_time = time.time()
        icmpSocket.settimeout(timeout)
        
        try:
            data, address = icmpSocket.recvfrom(1024)
            # print(f"Received {len(data)} bytes from {address}")

            end_time = time.time()
            delay = end_time - start_time

            # Unpack the packet header for useful information
            icmpHeader = data[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmpHeader)

            # Check that the ID and sequence number match between the request and reply
            if packet_ID == self.ID and sequence == ttl:
                return delay, address[0]
        
        except socket.timeout:
            # Handle a timeout
            return None, None
        
        # Return the delay and address even if packet_ID and sequence number do not match
        return delay, address[0]



    def sendOnePing(self, icmpSocket, dest_addr, ttl):
        header = struct.pack("bbHHh", 8, 0, 0, self.ID, 1)
        payload = b"abcdefghijklmnopqrstuvwxyz"
        packet = header + payload

        # Set the TTL
        ttl = struct.pack('I', ttl)
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Compute the checksum
        myChecksum = self.checksum(packet)
        header = struct.pack("bbHHh", 8, 0, myChecksum, self.ID, 1)
        packet = header + payload

        # Send the packet
        icmpSocket.sendto(packet, (dest_addr, 1))

        # Return the size of the packet and the TTL used
        packetSize = len(packet)
        ttlUsed = struct.unpack('I', ttl)[0]
        return packetSize, ttlUsed


    def doOneTrace(self, dest_name, timeout, ttl):
        dest_addr = socket.gethostbyname(dest_name)

        # Create ICMP socket
        icmp = socket.getprotobyname("icmp")
        try:
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as errorCode:
            if errorCode.errno == 1:
                # Operation not permitted - Add more information to the error message
                raise socket.error("ICMP messages can only be sent from processes running as root.")
            raise

        # Set the TTL for the socket
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))

        # Call sendOnePing function
        packetSize, ttlUsed = self.sendOnePing(icmpSocket, dest_addr, ttl)
        # print("Packet size: ", packetSize)
        # print("TTL used: ", ttlUsed)

        # Call receiveOnePing function
        delay, address = self.receiveOnePing(icmpSocket, timeout, ttl)
        # print("Delay: ", delay)
        # print("Address: ", address)
        # Close ICMP socket
        icmpSocket.close()

        return delay, address, packetSize, ttlUsed


    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        self.ID = random.randint(0, 65535)
        max_ttl = 64
        timeout = args.timeout

        # Perform traceroute for each TTL value
        for ttl in range(1, max_ttl + 1):
            print(f'{ttl}\t', end='', flush=True)
            done = False
            addresses = []
            for i in range(3):
                delay, address, packetSize, ttlUsed = self.doOneTrace(args.hostname, timeout, ttl)

                if delay is not None:
                        print(f'{address} ({delay * 1000:.3f} ms)\t', end='', flush=True)


class ParisTraceroute(NetworkApplication):

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Paris-Traceroute to: %s...' % (args.hostname))

class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
