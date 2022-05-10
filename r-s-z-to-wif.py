import bitcoin
import hashlib
import binascii
import pystyle

b58_digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

tx = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
z1 = 0xdfbd70a686ed250a0cca10132173dd79a124ed7ca794256eb34e3587377ce01f
z2 = 0x2314c8ef44ae906c58cabd7a10bdd4c472284a43770193b64b2ec5602e7a6ada

der_sig1 = "3044022035e4dd6e4d56638eee57fddf6af2d9f8a1cd8ae35d8e304b175f8c5ec0d80f6f02202b1c3c17b3d13a8e6c9ad6a75743feb2040dff9d741e53c7c5564baba7a09acb01"
der_sig2 = "3044022035e4dd6e4d56638eee57fddf6af2d9f8a1cd8ae35d8e304b175f8c5ec0d80f6f022024e0255335dc10284b3df9feadd1edc2bfb0540c03d1dbc09d65a84179f3b3a701"

params = {"p": p, "sig1": der_sig1, "sig2": der_sig2, "z1": z1, "z2": z2}

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new("ripemd160")
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def base58_encode(n):
    tmp = []
    while n > 0:
        n, r = divmod(n, 58)
        tmp.insert(0, (b58_digits[r]))
    return "".join(tmp)

def base58_encode_padded(s):
    a = binascii.hexlify(s).decode("utf8")
    if len(a) % 2 != 0:
        a = "0" + a
    res = base58_encode(int("0x" + a,16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return (b58_digits[0] * pad) + res

def base58_check_encode(s, version=0):
    vs = version.to_bytes(1, byteorder='big') + s 
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def py2_get_der_field(i, binary):
    if ord(binary[i]) == 2:
        length = binary[i + 1]
        end = i + ord(length) + 2
        string = binary[i + 2 : end]
        return string
    else:
        return None

def get_der_field(i, binary):
    if binary[i] == 2:
        length = binary[i + 1]
        end = i + length + 2
        string = binary[i + 2 : end] 
        return string
    else:
        return None

def der_decode(hexstring):
    binary = binascii.unhexlify(hexstring)
    full_length = binary[1]
    if (full_length + 3) == len(binary):
        r = get_der_field(2, binary)
        s = get_der_field(len(r) + 4, binary)
        return r, s
    else:
        return None

def show_results(privkeys):
    print("Posible Candidates...")
    for privkey in privkeys:
        address = bitcoin.privtoaddr(privkey)
        hexprivkey = "%064x" % privkey
        wif = base58_check_encode(binascii.unhexlify(hexprivkey), version=128)
        wifc = base58_check_encode(binascii.unhexlify(hexprivkey + "01"), version=128)
        print(pystyle.Box.DoubleCube(f"address: {address}\nintPrivkey: {privkey}\nhexPrivkey: {hexprivkey}\nbitcoin Privkey (WIF): {wif}\nbitcoin Privkey (WIF compressed): {wifc}"))

def inverse_mult(a, b, p):
    y = (a * pow(b, p - 2, p)) % p
    return y

def derivate_privkey(p, r, s1, s2, z1, z2):
    privkey = []

    s1ms2 = s1 - s2
    s1ps2 = s1 + s2
    ms1ms2 = -s1 - s2
    ms1ps2 = -s1 + s2
    z1ms2 = z1 * s2
    z2ms1 = z2 * s1
    z1s2mz2s1 = z1ms2 - z2ms1
    z1s2pz2s1 = z1ms2 + z2ms1
    rs1ms2 = r * s1ms2
    rs1ps2 = r * s1ps2
    rms1ms2 = r * ms1ms2
    rms1ps2 = r * ms1ps2

    privkey.append(inverse_mult(z1s2mz2s1, rs1ms2, p))
    privkey.append(inverse_mult(z1s2mz2s1, rs1ps2, p))
    privkey.append(inverse_mult(z1s2mz2s1, rms1ms2, p))
    privkey.append(inverse_mult(z1s2mz2s1, rms1ps2, p))
    privkey.append(inverse_mult(z1s2pz2s1, rs1ms2, p))
    privkey.append(inverse_mult(z1s2pz2s1, rs1ps2, p))
    privkey.append(inverse_mult(z1s2pz2s1, rms1ms2, p))
    privkey.append(inverse_mult(z1s2pz2s1, rms1ps2, p))

    return privkey

def process_signatures(params):

    p = params["p"]
    sig1 = params["sig1"]
    sig2 = params["sig2"]
    z1 = params["z1"]
    z2 = params["z2"]

    tmp_r1, tmp_s1 = der_decode(sig1)
    tmp_r2, tmp_s2 = der_decode(sig2)

    r1 = int(binascii.hexlify(tmp_r1), 16)
    r2 = int(binascii.hexlify(tmp_r2), 16)
    s1 = int(binascii.hexlify(tmp_s1), 16)
    s2 = int(binascii.hexlify(tmp_s2), 16)

    if r1 == r2:
        if s1 != s2:
            privkey = derivate_privkey(p, r1, s1, s2, z1, z2)
            return privkey
        else:
            raise Exception("Privkey not computable: s1 and s2 are equal.")
    else:
        raise Exception("Privkey not computable: r1 and r2 are not equal.")

def main():
    privkey = process_signatures(params)
    if len(privkey) > 0: show_results(privkey)

if __name__ == "__main__":
    main()