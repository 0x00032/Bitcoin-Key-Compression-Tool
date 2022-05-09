import sys
import requests

def getraw(transaction):
	url = f'https://sochain.com/api/v2/tx/BTC/{transaction}'
	response = requests.get(url).json()["data"]["tx_hex"]
	print("\n\n##################################################################################################")
	print("################################## VALUES NEEDED ARE BELOW #######################################")
	print("##################################################################################################\n")
	print(f'Raw Transaction: {response}')

if __name__ == '__main__':
	if len(sys.argv) == 1:
		tid = input("Enter Transaction Hash:  ")
	elif len(sys.argv) == 2 and isinstance(sys.argv[1], str):
		tid = str(sys.argv[1])
	getraw(tid)