import codecs
import hashlib
import txnUtils
import keyUtils

tx = "010000000103a29fa026780a95fc7c4daa8f320e05c34b734ad61f14aae9efcf45e245d41f010000008a473044022035e4dd6e4d56638eee57fddf6af2d9f8a1cd8ae35d8e304b175f8c5ec0d80f6f022024e0255335dc10284b3df9feadd1edc2bfb0540c03d1dbc09d65a84179f3b3a70141042834d5c5245111b414f173079ce88c496609dddf8aae5dc4ffcfa6a3dd4475afba06f5c919a1d6ea0c1ccf3d62eee2090928fb554879c72b2ce19f7f40585425ffffffff0180841e00000000001976a91401bfa577df1e21ee9b1e14329ba1d06403f4fdb988ac00000000"

m = txnUtils.parseTxn(tx)
e = txnUtils.getSignableTxn(m)
z = hashlib.sha256(hashlib.sha256(e).digest()).digest()
z1 = codecs.encode(z[::-1], encoding='hex_codec')
z = codecs.encode(z, encoding='hex_codec')
s = keyUtils.derSigToHexSig(m[1][:-2])

pub =  m[2]
sigR = s[:64]
sigS = s[-64:]
sigZ = codecs.decode(z, encoding='UTF-8')

print(f"""
Signed TX is :' {tx}
Signature (r, s pair) is : {s}
Public Key is: {pub}
#################################################################################################

Unsigned TX is: {e}
hash of message (sigZ) is (USE THIS ONE): {sigZ}
reversed z: {codecs.decode(z1, encoding='UTF-8')}

##################################################################################################
################################## VALUES NEEDED ARE BELOW #######################################
##################################################################################################

THE R VALUE is: {sigR}
THE S VALUE is: {sigS}
THE Z VALUE is: {sigZ}

THE PUBKEY is: {pub}
""")