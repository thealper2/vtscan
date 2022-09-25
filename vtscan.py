import requests
import argparse
import os
import time
import datetime
import json
import colorama
import pyfiglet
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

def print_banner():
	version = 0.1
	print("""                .                                           """)
	print("""              .o8                                           """)
	print("""oooo    ooo .o888oo  .oooo.o  .ooooo.   .oooo.   ooo. .oo.  """)
	print(""" `88.  .8'    888   d88(  "8 d88' `"Y8 `P  )88b  `888P"Y88b """)
	print("""  `88..8'     888   `"Y88b.  888        .oP"888   888   888 """)
	print("""   `888'      888 . o.  )88b 888   .o8 d8(  888   888   888 """)
	print("""    `8'       "888" 8""888P' `Y8bod8P' `Y888""8o o888o o888o""")
	print()
	print(" "*10,"Author:", f"{Back.BLUE}{Fore.RED}Alper Karaca", "Version:", version)
	print()

def check_apikey(api_key):
	if len(api_key) == 64:
		return api_key
	else:
		print("Wrong API Key.")
		exit()

def check_hash_length(hashes):
	if len(hashes) == 32:
		return hashes
	elif len(hashes) == 48:
		return hashes
	elif len(hashes) == 64:
		return hashes
	else:
		print("This hash input is missing or invalid. Note: MD5 is 32 digits long, SHA-1 is 48 digits long and SHA-256 is 64 digits long.")
		exit()

def check_url(url):
	return url

def check_ip(ipaddr):
	return ipaddr

def VT_URL(api_key, url):
	vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
	parameters = {'apikey': api_key, 'resource': url}
	vt_response = requests.get(vt_url, params=parameters)
	vt_keys = json.loads(vt_response.text)
	vt_response_json = json.loads(vt_response.content)
	date = datetime.datetime.now().strftime("%d_%m_%Y-%I:%M:%S_%p")
	filename = "vtscan_" + date  
	file = open(filename + ".txt", "w+")

	print(f"{Style.BRIGHT}-> Information")
	file.write("-> Information" + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}URL: ", vt_keys['resource'])
	file.write("* URL: " + vt_keys['resource'] + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}Date: ", vt_keys['scan_date'])
	file.write("* Date: " + vt_keys['scan_date'] + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}Count: ", vt_keys['positives'], "/", vt_keys['total'])
	file.write("* Count: " + str(vt_keys['positives']) + "/" + str(vt_keys['total']) + "\n\n")
	print()

	print(f"{Style.BRIGHT}{Back.RED}{Fore.WHITE}+-----------ANTIVIRUS------------+-DETECTED-+------RESULT------+----W---+")
	file.write("+----------ANTIVIRUS----------+-DETECTED-+-----RESULT-----+\n")
	for key, value in vt_keys['scans'].items():
		bool_space = 5 if value['detected'] == True else 4
		level = "\U0000274C" if value['detected'] == True else "\U0000274E"
		print("I ", key, " "*(28-len(key)), "I ", value['detected'], " "*(bool_space-3), "I ", value['result'], " "*(14-len(value['result'])), "I  ", level, " "*1, "I")
		file.write("I " + key + " "*(28-len(key)) + "I " + str(value['detected']) + " "*(bool_space) + "I " + value['result'] + " "*(15-len(value['result'])) + "I" + "\n")
	print(f"{Style.BRIGHT}{Back.RED}{Fore.WHITE}+--------------------------------+----------+------------------+--------+")
	file.write("+--------------------------------+----------+-------------+" + "\n\n")
	link = vt_keys['permalink']
	print("\n", f"{Fore.RED}*", f"{Style.BRIGHT}View on VirusTotal: ", f"\u001b]8;;{vt_keys['permalink']}\u001b\\{link}\u001b]8;;\u001b\\")
	file.write("* View on VirusTotal: " + str(vt_keys['permalink']) + "\n")
	file.close()

def VT_HASH(api_key, file_hash):
	vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
	parameters = {'apikey': api_key, 'resource': file_hash}
	vt_response = requests.get(vt_url, params=parameters)
	vt_keys = vt_response.json()
	date = datetime.datetime.now().strftime("%d_%m_%Y-%I:%M:%S_%p")
	filename = "vtscan_" + date  
	file = open(filename + ".txt", "w+")

	print(f"{Style.BRIGHT}-> Information")
	file.write("-> Information" + "\n") 
	print(f"{Fore.RED}*", f" {Style.BRIGHT}MD5: ", vt_keys.get('md5'))
	file.write("* MD5: " + vt_keys.get('md5') + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}SHA-1: ", vt_keys.get('sha1'))
	file.write("* SHA-1: " + vt_keys.get('sha1') + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}SHA-256: ", vt_keys.get('sha256'))
	file.write("* SHA-256: " + vt_keys.get('sha256') + "\n")
	print(f"{Fore.RED}*", f" {Style.BRIGHT}Date: ", vt_keys.get('scan_date'))
	file.write("* Date: " + vt_keys.get('scan_date') + "\n" )
	print(f"{Fore.RED}*", f" {Style.BRIGHT}Count: ", vt_keys.get('positives'), "/", vt_keys.get('total'))
	file.write("* Count: " + str(vt_keys.get('positives')) + "/" + str(vt_keys.get('total')) + "\n\n")
	print()

	print(f"{Style.BRIGHT}{Back.RED}{Fore.WHITE}+-------------ANTIVIRUS------------+-DETECTED-+------------------------RESULT------------------------+----W---+")
	file.write("+-----------ANTIVIRUS-----------+-DETECTED-+----------------------RESULT-----------------------+\n")
	for key, value in vt_keys.get('scans').items():
		bool_space = 5 if value['detected'] == True else 4
		level = "\U0000274C" if value['detected'] == True else "\U0000274E"
		print("I ", key, " "*(30-len(str(key))), "I ", value['detected'], " "*(bool_space-3), "I ", value['result'], " "*(50-len(str(value['result']))), "I  ", level, " "*1, "I")	
		file.write("I " + str(key) + " "*(30-len(str(key))) + "I " + str(value['detected']) + " "*(bool_space) + "I " + str(value['result']) + " "*(50-len(str(value['result']))) + "I" + "\n")
	print(f"{Style.BRIGHT}{Back.RED}{Fore.WHITE}+----------------------------------+----------+------------------------------------------------------+--------+")
	file.write("+-------------------------------+----------+---------------------------------------------------+" + "\n\n")
	print()
	link = vt_keys['permalink']
	print("\n", f"{Fore.RED}*", f" {Style.BRIGHT}View on VirusTotal: ", f"\u001b]8;;{vt_keys['permalink']}\u001b\\{link}\u001b]8;;\u001b\\")
	file.write("* View on VirusTotal: " + str(vt_keys['permalink']) + "\n")
	file.close()

def main():
	argument_parser = argparse.ArgumentParser(description="Scan hashes, urls and ip addresses in VirusTotal.")
	argument_parser.add_argument('-k', '--key', type=check_apikey, required=True, help='VT API Key')
	argument_parser.add_argument('-x', '--hash', type=check_hash_length, required=False, help='Hash (MD5, SHA-1, SHA-256)')
	argument_parser.add_argument('-i', '--ip', type=check_ip, required=False, help='IP Address')
	argument_parser.add_argument('-u', '--url', type=check_url, required=False, help='URL')
	arguments = argument_parser.parse_args()

	if arguments.url and arguments.key and not arguments.hash:
		print_banner()
		VT_URL(arguments.key, arguments.url.rstrip())

	elif arguments.hash and arguments.key and not arguments.url:
		print_banner()
		VT_HASH(arguments.key, arguments.hash.strip())

if __name__ == "__main__":
	main()







