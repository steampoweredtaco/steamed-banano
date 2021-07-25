import hashlib
import binascii
import struct, io
from decimal import Decimal
import ed25519_blake2b


RAW_MULTI = 100000000000000000000000000000
ACCOUNT_LOOKUP = "13456789abcdefghijkmnopqrstuwxyz"
ACCOUNT_PUBLIC = "ban_3wtsduys8b7jkbfwwfzx3jgpgpsi9b8zurfe9bp1p5cdxkqiz7a5wxcoo7ba"
WALLETKEY = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

def get_public(private):
    secret = binascii.unhexlify(private)
    key = ed25519_blake2b.SigningKey(secret)
    pkey = key.get_verifying_key().to_bytes()
    return binascii.hexlify(pkey)

def get_raw(banano_cnt):
    return int(RAW_MULTI * banano_cnt)

def get_banano(raw_cnt):
    return int(raw_cnt / Decimal(RAW_MULTI))

def generate_priv(seed, index=0):
    bin = binascii.unhexlify(seed);
    indx = struct.pack('!I', index)
    dig = hashlib.blake2b(digest_size=32)
    dig.update(bin)
    dig.update(indx)
    return dig.hexdigest().upper()
    

def encode_to_32(bytes):
    int_val = int.from_bytes(bytes, 'little')
    result = io.StringIO()
    for _ in range(0, int(Decimal(len(bytes)*8)/Decimal(5))):
        l_indx = int_val & 0x1f
        result.write(ACCOUNT_LOOKUP[l_indx])
        int_val = int_val >> 5
    return result.getvalue()

def encode_account(hexstring):
    account_bin = binascii.unhexlify(hexstring)
    account = int.from_bytes(account_bin, 'big')
    hash = hashlib.blake2b(digest_size=5)
    hash.update(account_bin)
    hash_b = hash.digest()
    checksum = int.from_bytes(hash_b, 'little')
    final_key = (account << 40) | checksum
    str_io = io.StringIO()
    for _ in range(0, 60):
        l_indx = final_key % 32
        str_io.write(ACCOUNT_LOOKUP[l_indx])
        final_key = final_key >> 5
    return 'ban_{}'.format(str_io.getvalue()[::-1])

print("Sanity check, private key {} will give this as the first public key {}".format(WALLETKEY, ACCOUNT_PUBLIC))
print("{} == {}".format(encode_account(get_public(generate_priv(WALLETKEY, 0))), ACCOUNT_PUBLIC))
for indx in range(0, 20):
    priv = generate_priv(WALLETKEY, indx)
    public = get_public(priv)
    print(indx, encode_account(public))

