from datetime import timedelta
from secrets import choice
from ssl import Options
import requests
import argparse
import concurrent
import concurrent.futures
from cryptography.hazmat.primitives import padding


START_URI = ""
ERROR_URI = ""
TIME_URI = ""
CHECK_URI = ""


def main():
    parser = argparse.ArgumentParser(
        description="AES Oracle Padding attack",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-m", "--mode", choices=("error", "time"), help="oracle mode")
    parser.add_argument(
        "-s",
        "--sequential",
        help="sequential mode for time oracle",
        action="store_true",
    )
    parser.add_argument("-n", "--name", help="name", type=str)
    args = parser.parse_args()
    config = vars(args)
    print(f"Name: {args.name}")
    stringRequest = requests.get(f"{START_URI}{args.name}")

    blockSize = 16
    cookies = stringRequest.cookies
    encrypted_strings = stringRequest.json()

    if args.mode == "error":
        e = bytearray.fromhex(encrypted_strings["error"])
        c = [e[i : i + blockSize] for i in range(0, len(e), blockSize)]
        print(f"Dividing blocks to {len(c)-1} processes")
        executor = concurrent.futures.ProcessPoolExecutor(len(c) - 1)
        futures = [
            executor.submit(decryptAESError, c, i, blockSize, cookies)
            for i in range(0, len(c) - 1)
        ]
        concurrent.futures.wait(futures)
        testPlainText(futures, cookies, oracle="error")
    if args.mode == "time":
        e = bytearray.fromhex(encrypted_strings["time"])
        c = [e[i : i + blockSize] for i in range(0, len(e), blockSize)]
        if args.sequential:
            plaintext = decryptAESTimesec(c, blockSize, cookies)
            testPlainTextSec(plaintext, cookies, oracle="time")
        else:
            print(f"Dividing blocks to {len(c)-1} processes")
            executor = concurrent.futures.ProcessPoolExecutor(len(c) - 1)
            futures = [
                executor.submit(decryptAESTime, c, i, blockSize, cookies)
                for i in range(0, len(c) - 1)
            ]
            concurrent.futures.wait(futures)
            testPlainText(futures, cookies, oracle="time")


# stringRequest.elapsed.total_seconds()
def decryptAESError(c, i, blockSize, cookies):
    c1 = c[i]
    c2 = c[i + 1]
    paddings = []
    print(f"\n[Error Oracle]Trying decrypting block {i+1} \nc1: {c1}\nc2: {c2}")

    # for every byte test oracle
    cprime = bytearray(len(c1))
    plain = bytearray(len(c1))
    yy = bytearray(len(c1))
    for j in range(blockSize - 1, -1, -1):

        # fill other positions
        for pos in range(blockSize - 1, j, -1):
            cprime[pos] = yy[pos] ^ (blockSize - j)
        valid_pad = False
        for newvalue in range(0, 256):
            cprime[j] = newvalue
            r = requests.get(
                f"{ERROR_URI}{cprime.hex()}{c2.hex()}",
                cookies=cookies,
                timeout=60,
            )
            if r.status_code == 404:
                # valid padding
                paddings.append(newvalue)
                valid_pad = True
                # print(f"Valid padding cprime[{j}] x:{newvalue} \n")
                y = newvalue ^ (blockSize - j)
                yy[j] = y
                plain[j] = y ^ c1[j]
                break

        if valid_pad == False:
            print(f"No valid pad found at  c{i} pos:{j}")
            exit()

    print(f"c2[{i}] Plain text: {plain}")
    print(f"c2[{i}] Correct padding: {paddings}")
    return plain


def decryptAESTime(c, i, blockSize, cookies):
    c1 = c[i]
    c2 = c[i + 1]
    print(f"\n[Time Oracle]Trying decrypting block {i+1} \nc1: {c1}\nc2: {c2}")

    # for every byte test oracle
    cprime = bytearray(len(c1))
    plain = bytearray(len(c1))
    yy = bytearray(len(c1))
    maxtime = 0
    maxtimevalue = 0
    for j in range(blockSize - 1, -1, -1):

        # fill other positions
        for pos in range(blockSize - 1, j, -1):
            cprime[pos] = yy[pos] ^ (blockSize - j)

        found = False
        newvalue = 0
        while not found:

            cprime[j] = newvalue
            r = requests.get(
                f"{TIME_URI}{cprime.hex()}{c2.hex()}",
                cookies=cookies,
                timeout=120,
            )
            newtime = r.elapsed.total_seconds()
            if newtime >= 0.19:
                # after some inspection of the elapsed time 0.19 is the min a correct padding answer should take
                found = True
                maxtime = newtime
                maxtimevalue = newvalue
            newvalue = newvalue + 1
            if newvalue == 256:
                # sometimes the oracle misbehaves so we have to retry again
                print(f"[{i}]Pad not found  j:{j} Retrying")
                newvalue = 0

        print(f"[{i}]MaxTime: {maxtime} Padding:{maxtimevalue}")
        y = maxtimevalue ^ (blockSize - j)
        yy[j] = y
        plain[j] = y ^ c1[j]
        maxtime = 0
        maxtimevalue = 0

    print(f"c2[{i}] Plain text: {plain}")
    return plain


def decryptAESTimesec(c, blockSize, cookies):
    plaintexts = bytearray()
    for i in range(len(c)-1):
        c1 = c[i]
        c2 = c[i + 1]
        print(f"\n[Time Oracle]Trying decrypting block {i+1} \nc1: {c1}\nc2: {c2}")

        # for every byte test oracle
        cprime = bytearray(len(c1))
        plain = bytearray(len(c1))
        yy = bytearray(len(c1))
        maxtime = None
        maxtimevalue = 0
        for j in range(blockSize - 1, -1, -1):
            # times = []
            # fill other positions
            for pos in range(blockSize - 1, j, -1):
                cprime[pos] = yy[pos] ^ (blockSize - j)

            for newvalue in range(0, 256):

                cprime[j] = newvalue
                r = requests.get(
                    f"{TIME_URI}{cprime.hex()}{c2.hex()}",
                    cookies=cookies,
                    timeout=120,
                )
                newtime = r.elapsed
                if newvalue == 0:
                    maxtime = r.elapsed
                if newtime > maxtime:
                    maxtime = newtime
                    maxtimevalue = newvalue

            print(f"[{i}]MaxTime: {maxtime} Padding:{maxtimevalue}")
            y = maxtimevalue ^ (blockSize - j)
            yy[j] = y
            plain[j] = y ^ c1[j]
            maxtime = 0
            maxtimevalue = 0
        plaintexts = plaintexts + plain
        print(f"c2[{i}] Plain text: {plain}")
    return plaintexts


def testPlainText(plaintextsFuture, cookies, oracle="error"):
    out = bytearray()
    for plaintext in plaintextsFuture:
        out = out + plaintext.result()
    print(out)
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(out)
    data = data + unpadder.finalize()
    url = f"{CHECK_URI}{oracle}/{data.decode()}"
    print(f"Plaintext: {data.decode()}")
    r = requests.get(url, cookies=cookies)
    print(r.text)


def testPlainTextSec(plaintexts, cookies, oracle="error"):
    out = bytearray()
    for plaintext in plaintexts:
        out = out + plaintext
    print(out)
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(out)
    data = data + unpadder.finalize()
    url = f"{CHECK_URI}{oracle}/{data.decode()}"
    print(f"Plaintext: {data.decode()}")
    r = requests.get(url, cookies=cookies)
    print(r.text)


if __name__ == "__main__":
    main()
