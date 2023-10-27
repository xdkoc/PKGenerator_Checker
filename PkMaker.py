import secrets
import codecs
import ecdsa
import hashlib
import base58
import asyncio
import aiohttp
import logging
import time

logging.basicConfig(filename='BTC_PrivateKeys_' + time.strftime("%Y-%m-%d-%H-%M") + '.csv',
                    level=logging.INFO, format='%(message)s', datefmt='%Y-%m-%d,%H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("blockcypher").setLevel(logging.WARNING)
logging.info('"Date" "Time" "Key" "PublicAddress" "Transactions"')

async def ping_address(session, publicAddress, wif):
    try:
        async with session.get("https://blockstream.info/api/address/" + publicAddress) as resp:
            if resp.status == 200:
                ourJSON = await resp.json()
                trans = ourJSON['chain_stats']['tx_count']
                balance = ourJSON['chain_stats']['funded_txo_sum']
                print(balance)

                logging.info(time.strftime("%d-%m-%y %H:%M ") + wif + " " + publicAddress + " " + str(trans))

                if float(balance) > 0.00000000:
                    logging.info(''+ time.strftime("%m-%d-%y %H:%M:%S") +','+ wif +','+publicAddress+' ,balance '+str(balance))
                    print("Congratulations...alert the world cause you just made some sort of history friend!")
                    print(wif)
                    with open('results.txt', 'a+') as f:
                        f.write(''+ time.strftime("%m-%d-%y %H:%M:S") +','+ wif +','+publicAddress+' ,balance '+str(balance))
    except (aiohttp.ClientError, ValueError, KeyError):
        print("An error occurred")

async def main():
    async with aiohttp.ClientSession() as session:
        while True:
            pk = secrets.token_hex(32)
            padding = '80' + pk
            hashedVal = hashlib.sha256(codecs.decode(padding, 'hex')).hexdigest()
            checksum = hashlib.sha256(codecs.decode(hashedVal, 'hex')).hexdigest()[:8]
            payload = padding + checksum
            wif = base58.b58encode(codecs.decode(payload, 'hex')).decode('utf-8')

            sk = ecdsa.SigningKey.from_string(codecs.decode(pk, "hex"), curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            publicKey = "\04" + str(vk.to_string())
            ripemd160 = hashlib.new('ripemd160')
            ripemd160.update(hashlib.sha256(codecs.encode(publicKey)).digest())
            networkAppend = b'\00' + ripemd160.digest()
            checksum = hashlib.sha256(hashlib.sha256(networkAppend).digest()).digest()[:4]
            binary_address = networkAppend + checksum
            publicAddress = base58.b58encode(binary_address).decode('utf-8')
            print(publicAddress)

            await ping_address(session, publicAddress, wif)

if __name__ == "__main__":
    asyncio.run(main())
