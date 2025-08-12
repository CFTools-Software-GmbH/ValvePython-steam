#!/usr/bin/env python3
import os
import time
import json
import urllib.request

from urllib.parse import quote

OWNER = "SteamDatabase"
REPO = "SteamTracking"
BRANCH = "master"  # matches your example
PATH = "Protobufs"

api_url = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{PATH}?ref={BRANCH}"

items: list = list()
with urllib.request.urlopen(api_url) as resp:
	data = json.load(resp)

	raw_base = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}/{PATH}/"

	for item in data:
		if item.get("type") == "file" and item.get("name", "").endswith(".proto"):
			items.append(item.get("name"))
			
	urls = [
		raw_base + quote(item["name"])
		for item in data
		if item.get("type") == "file" and item.get("name", "").endswith(".proto")
	]

if os.path.isfile('protobuf_list.txt'):
	os.rename('protobuf_list.txt', f'protobuf_list-{int(time.time())}.txt')
	
with open('protobuf_list.txt', 'w') as f:
	for url in urls:
		f.write(url+'\n')

print('_proto_modules = [')
for item in items:
	print("\t'{}',".format(item.replace('.proto', '_pb2').replace('.steamclient', '')))
print(']')