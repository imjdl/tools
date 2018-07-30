#!/usr/bin/env python3
#coding=UTF-8

import requests
import os
import sys
from urllib.parse import urlparse
import zlib
import re
from threading import Thread

from gitindex.parser import parse

file_path = os.path.dirname(os.path.abspath(__file__))
file_name = file_path + '/' + 'index'


# 读取index文件
def getindex(url):

    url = url + 'index'
    r = requests.get(url=url)
    if r.status_code != 200:
        print('ERROR CODE')
        sys.exit(0)

    if os.path.exists('index'):
        os.remove('index')

    with open('index', 'wb') as f:
        f.write(r.content)

    res = parse(file_name)
    files = []
    for i in res:
        val = {}
        try:
            val["name"] = i['name']
            val["hash"] = i['sha1']
        except KeyError:
            continue
        files.append(val)
    os.remove('index')
    return files


# 根据 index文件到objects文件夹下下载
def getfiles(base_url, files, domain_path):
    domain_path = domain_path + '/'
    for f in files:
        Thread(target=getfile, args=(base_url, f, domain_path)).start()

def getfile(base_url, f, domain_path):
    base_url = base_url + 'objects/{0}/{1}'
    try:
        url = base_url.format(f['hash'][:2], f['hash'][2:])
        r = requests.get(url)
        res = zlib.decompress(r.content)
        res = res.decode('ascii')
        res = re.sub('blob \d+\00', '', res)
        if '/' in f['name']:
            file_dir = ''
            dirname = f['name'].split('/')
            name = dirname.pop()
            for d in dirname:
                file_dir = file_dir + d + '/'
            print(domain_path + file_dir)
            try:
                os.makedirs(domain_path + file_dir)
                print(domain_path + file_dir + name)
                with open(domain_path + file_dir + name, 'w') as sc:
                    sc.write(res)
            except FileExistsError:
                with open(domain_path + file_dir + name, 'w') as sc:
                    sc.write(res)
        else:
            print(domain_path + f['name'])
            with open(domain_path + f['name'], 'w') as sc:
                sc.write(res)
    except UnicodeDecodeError:
        print(f['name'], 'create error')

if __name__ == '__main__':

    url = 'http://172.28.100.85/.git'
    if url[-1] != '/':
        url = url + '/'

    domain= urlparse(url).netloc
    domain_path = file_path + '/' + domain
    if not os.path.exists(domain_path):
        os.mkdir(domain_path)
    files = getindex(url)
    print(files)
    getfiles(url, files, domain_path)
