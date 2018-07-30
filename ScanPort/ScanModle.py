#!/usr/bin/env python3
#coding = UTF-8
__author__ = "EK"
__doc__ = """
扫描端口
用法：
send.py -t 192.168.1.1 -p 80_8080_3306_445
send.py -t 192.168.1.1 -p 80-3306
send.py -t 192.168.1.1/24 -p 80
send.py -t 192.168.1.1/16 -p 3306
"""

import socket
import sys
import os
from struct import *
from random import shuffle
import netifaces
from threading import Thread
from multiprocessing import Process
import signal
import argparse


# 指定数据包出口网卡
NETWORKCARD = "enp2s0f5"
# 超时时间 s
TIMEOUT = 2
# 退出循环的FlAG
FLAG = False


class send(Process):

    def __init__(self, dst_ips, dst_ports, src_port=10086):
        super(send, self).__init__()
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # 自己创建IP头部
        except socket.error:
            print("Socket 创建失败")
            sys.exit()
        self.dst_ips , self.mask = self._make_ips(dst_ips)
        self.dst_ports = self._make_ports(dst_ports)
        shuffle(self.dst_ips)
        shuffle(self.dst_ports)
        self.src_port = src_port
        self.src_ip = netifaces.ifaddresses(NETWORKCARD)[2][0]['addr']
        self.packets = self._make_packets()

    # 数据包集合
    def _make_packets(self):
        packets = []
        for ip in self.dst_ips:
            for port in self.dst_ports:
                packets.append(self._make_packet(dst_ip= ip, dst_port= port, syn=1))
        return packets

    # 单独数据包
    def _make_packet(self, dst_ip, dst_port, syn):
        """
        生成 IP头部 TCP头部
        :return:数据包
        """
        packet = ''

        # ip 头部的字段
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0
        ip_id = 2333
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(self.src_ip)
        ip_daddr = socket.inet_aton(dst_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                         ip_check, ip_saddr, ip_daddr)
        # 计算校验和
        ip_check = self.checksum(ip_header)

        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                         ip_check, ip_saddr, ip_daddr)

        # tcp头部的一些字段
        tcp_source = self.src_port  # 源端口
        tcp_dest = dst_port  # 目标端口
        tcp_seq = 454
        tcp_ack_seq = 0
        tcp_doff = 5
        tcp_fin = 0
        tcp_syn = syn
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window, tcp_check, tcp_urg_ptr)

        # TCP伪首部 共12个字节  源IP 目的IP 保留字节(置0)、传输层协议号(TCP是6)、TCP报文长度(报头+数据)
        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
        psh = psh + tcp_header

        tcp_check = self.checksum(psh)
        tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
        packet = ip_header + tcp_header

        return packet, (dst_ip, dst_port)

    # 计算校验码
    def checksum(self, msg):

        s = 0
        for i in range(0, len(msg)-1, 2):
            tmp = (msg[i + 1]<<8) + msg[i]
            s += tmp
            s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def sendpacket(self, packets):
        # self.s.sendto(self.packets, ("172.28.100.1", 80))
        for packet in packets:
            p, target = packet
            try:
                self.s.sendto(p, target)
            except PermissionError:
                continue

        # self.s.close()

    def _make_ips(self, ips):
        """
        ips : 192.168.1.1 or 192.168.1.1/24 or 192.168.1.1/16
        return ([], None) or ([],"/")
        """
        try:
            netips, mask = ips.split('/')
        except ValueError:
            netips = ips.split('/')
            return netips, None
        if mask == '24':
            ips = netips.split('.')
            ips.pop()
            ips = ".".join(ips)
            return [ips + "." + str(i) for i in range(1, 256)], mask
        elif mask == '16':
            ips = netips.split('.')
            ips.pop()
            ips.pop()
            ips = ".".join(ips)
            return [ips + "." + str(i) + "." + str(j) for i in range(1, 256) for j in range(1, 256)], mask
        else:
            print("目的IP格式错误")
            sys.exit(-1)

    def _make_ports(self, ports):
        """
        ports: 80 or 80_3306_60 or 80-3306
        :return:[]
        """

        if "_" not in ports and "-" not in ports:
            try:
                return [int(ports)]
            except ValueError:
                print("端口格式错误")
                sys.exit(-1)

        elif "_" in ports and "-" not in ports:
            try:
                return [int(x) for x in ports.split("_")]
            except ValueError:
                print("端口格式错误")
                sys.exit(-1)

        elif "-" in ports and "_" not in ports:
            try:
                ber, aft = ports.split("-")
                ber = int(ber)
                aft = int(aft)
                return [x for x in range(ber, aft+1)]
            except ValueError:
                print("端口格式错误")
                sys.exit(-1)
        else:
            print("端口格式错误")
            sys.exit(-1)

    def run(self):
        part = 20
        # 将大列表分为小列表， 多线程发包
        part_packets = [self.packets[i:i+part] for i in range(0, len(self.packets), part)]
        for p in part_packets:
            t = Thread(target=self.sendpacket, args=(p, ))
            t.start()
            t.join()
        self.s.close()

    # def __del__(self):
    #     self.s.close()


class getdata(Process):

    def __init__(self, src_port=10086):
        super(getdata, self).__init__()
        self.src_port = src_port
        try:
            host = netifaces.ifaddresses(NETWORKCARD)[2][0]['addr']
        except KeyError:
            sys.exit(0)
        try:
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # 设置超时时间
            self.sniffer.settimeout(TIMEOUT)
            self.sniffer.bind((host, self.src_port))
        except socket.error:
            sys.exit(0)

    def run(self):
        global FLAG
        p = pms()
        while True:
            try:
                raw_buffer = self.sniffer.recvfrom(65535)[0]
            except socket.timeout:
                pass
            dst_port, src_port, tcp_flag = self.getTCP(raw_buffer[20:40])
            if dst_port == self.src_port and tcp_flag == 18:
                dst_ip = self.getIP(raw_buffer[:20])
                print(dst_ip, ":", src_port, ":", p.getserver(src_port))
            if FLAG:
                print("End!!!!")
                break;

    def getIP(self, data):
        iph = unpack('!BBHHHBBH4s4s', data)
        version = iph[0] >> 4
        ihl = iph[0] * 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        return s_addr

    def getTCP(self, data):
        tcph = unpack('!HHLLBBHHH', data)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        tcp_flag = tcph[5]
        return dest_port, source_port, tcp_flag

    def __del__(self):
        self.sniffer.close()


# 映射端口到服务 pms=> port mapping server
class pms():
    def __init__(self):
        self._porttoserver = {}
        path = os.path.dirname(os.path.abspath(__file__))
        servics_tcp = path + "/search_tcp"
        with open(servics_tcp) as stcp:
            for i in stcp.readlines():
                s, p = i.split("->")
                self._porttoserver[int(p)] = s

    def getserver(self, port):
        try:
            return self._porttoserver[port]
        except KeyError:
            return "unknown"


def handler(signum, frame):
    global FLAG
    FLAG = True


if __name__ == '__main__':
    parse = argparse.ArgumentParser(prog="EKMAP")
    parse.add_argument("-t", help="输入目标ip,可以为单个IP、C段、B段")
    parse.add_argument('-p', help="输入目标端口，可以为一个也可以指定范围如：80-1024，也可以指定特定端口：80_3306_445...")
    args = parse.parse_args()
    if args.t == None or args.p == None:
        parse.print_help()
        sys.exit(-1)
    # s = send('172.28.100.60/24', "80")
    # # 接受Ctrl + C 信号 执行handler 退出循环
    print("CTRL+C 停止")
    signal.signal(signal.SIGINT, handler)
    s = send(args.t, args.p)
    g = getdata()
    s.start()
    g.start()