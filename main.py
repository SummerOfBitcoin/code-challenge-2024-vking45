import os
import json
import hashlib
import ripemd.ripemd160
import time
import struct
import binascii

class Stack:
    def __init__(self):
        self.list = []

    def push(self, val):
        self.list.append(val)

    def isEmpty(self):
        return len(self.list) == 0

    def pop(self):
        if not self.isEmpty():
            val = self.list.pop(len(self.list) - 1)
            return val
        else:
            return None

    def peek(self):
        if not self.isEmpty():
            return self.list[len(self.list) - 1]
        else:
            return None

    def view(self):
        print(self.list)

# a helper function to convert a hex string to reverse hex string
def reverse_hex_string_bytearray(hex_string):
  byte_array = bytearray.fromhex(hex_string)
  byte_array.reverse()
  return byte_array.hex()

# a helper function to get the current timestamp for mining the block
def get_timestamp():
    current_timestamp = int(time.time())
    hex_bytes = struct.pack("<I", current_timestamp)
    hex_string = hex_bytes.hex()
    return hex_string

# a helper function to calculate ripemd160 hash of the input
def _ripemd160(hex_bytes):
    binary_data = binascii.unhexlify(hex_bytes)
    hash_object = ripemd.ripemd160.new(binary_data) 
    hex_digest = hash_object.digest()  
    return hex_digest.hex()

# a helper function to double sha256 hash of the input
def double_hash(data):
    single_hash = hashlib.sha256(bytes.fromhex(data))
    double_hash = hashlib.sha256(bytes.fromhex(single_hash.hexdigest())).hexdigest()
    return double_hash

# a helper function which takes a list of txids/wtxids as input and calculates the root of the merkle tree in a recursive manner
def merkleroot(txids):
    if len(txids) == 1:
        return txids[0]
    result = []
    for i in range(0, len(txids), 2):
        one = txids[i]
        two = txids[i + 1] if i + 1 < len(txids) else one
        concat = one + two
        result.append(double_hash(concat))
    return merkleroot(result)

# a helper function which takes the filename of the transaction as input, serializes the whole data in the correct manner and returns the double hash of the serialized data in reverse byte order
def getTxID(filename):
    with open(f"mempool/{filename}", 'r') as f:
        data = json.load(f)
        raw = ''
        raw += data['version'].to_bytes(4, byteorder='little').hex()

        raw += f"{len(data['vin']):02x}"

        for inp in data['vin']:
            raw += reverse_hex_string_bytearray(inp['txid'])
            raw += inp['vout'].to_bytes(4, byteorder='little').hex()
            scriptlen = f"{int(len(inp['scriptsig']) / 2):02x}"
            raw += scriptlen
            if scriptlen != "00":
                raw += inp['scriptsig']
            raw += inp['sequence'].to_bytes(4, byteorder='little').hex()

        raw += f"{len(data['vout']):02x}"

        for outp in data['vout']:
            raw += outp['value'].to_bytes(8, byteorder='little').hex()
            raw += f"{int(len(outp['scriptpubkey']) / 2):02x}"
            raw += outp['scriptpubkey']
        
        raw += data['locktime'].to_bytes(4, byteorder='little').hex()

        txid = reverse_hex_string_bytearray(double_hash(raw))
        
        return txid

# a helper function which takes the filename as input, serializes the whole data including the marker, flag and witness as well and returns the double has of the serialized data in reverse byte order
def wTxID(filename):
    with open(f"mempool/{filename}", 'r') as f:
        data = json.load(f)
        raw = ''
        raw += data['version'].to_bytes(4, byteorder='little').hex()

        for inp in data['vin']:
            if "witness" in inp.keys():
                raw += "0001"
                break

        raw += f"{len(data['vin']):02x}"

        for inp in data['vin']:
            raw += reverse_hex_string_bytearray(inp['txid'])
            raw += inp['vout'].to_bytes(4, byteorder='little').hex()
            scriptlen = f"{int(len(inp['scriptsig']) / 2):02x}"
            raw += scriptlen
            if scriptlen != "00":
                raw += inp['scriptsig']
            raw += inp['sequence'].to_bytes(4, byteorder='little').hex()

        raw += f"{len(data['vout']):02x}"

        for outp in data['vout']:
            raw += outp['value'].to_bytes(8, byteorder='little').hex()
            raw += f"{int(len(outp['scriptpubkey']) / 2):02x}"
            raw += outp['scriptpubkey']

        for inp in data['vin']:
            if "witness" in inp.keys():
                raw += f"{len(inp['witness']):02x}"
                for wit in inp['witness']:
                    raw += f"{int(len(wit) / 2):02x}"
                    raw += wit
        
        raw += data['locktime'].to_bytes(4, byteorder='little').hex()
        
        return reverse_hex_string_bytearray(double_hash(raw))

# the main loop which takes in the coinbase_txid as input and creates a list of valid txids and puts it in the merkleroot helper function to calculate merkleroot hash and returns the list of valid txs to write in the output.txt
def mempool(coinbase_txid):
    inval_txs = 0
    val_txs = []
    val_txs.append(coinbase_txid)
    folder = "mempool"
    for filename in os.listdir(folder):
        if verify_tx(filename):
            val_txs.append(getTxID(filename))
        else:
            inval_txs += 1
    print(f"Valid Transactions : {len(val_txs)}")
    print(f"Invalid Transactions : {inval_txs}")
    reverse_txids = []
    for i in val_txs:
        reverse_txids.append(reverse_hex_string_bytearray(i))
    merkle = merkleroot(reverse_txids)
    return (merkle, val_txs)

# the function which checks each json file at once to see if it is valid or not
def verify_tx(tx_filename):
    with open(f"mempool/{tx_filename}", 'r') as f:

        data = json.load(f)

        inp_amt = 0
        out_amt = 0

        txid_vout = []

        for inp in data["vin"]:

            if (inp["txid"], inp["vout"]) in txid_vout:
                return False

            txid_vout.append((inp["txid"], inp["vout"]))

            if inp["prevout"]["scriptpubkey_type"] == "p2pkh":
                stck = Stack()

                _sigscript = inp["scriptsig_asm"].split()
                (stck, valid1) = loop_opcodes(stck, _sigscript)

                _pubkeyscript = inp["prevout"]["scriptpubkey_asm"].split()
                (stck, valid2) = loop_opcodes(stck, _pubkeyscript)

                valid3 = process_scriptpubkey(_sigscript) == inp["scriptsig"]
                valid4 = process_scriptpubkey(_pubkeyscript) == inp["prevout"]["scriptpubkey"]

                if not valid1 or not valid2 or not valid3 or not valid4:
                    return False

            elif inp["prevout"]["scriptpubkey_type"] == "p2sh":
                stck = Stack()
                dup_stck = Stack()

                _sigscript = inp["scriptsig_asm"].split()
                (stck, valid1) = loop_opcodes(stck, _sigscript)
                (dup_stck, valid1) = loop_opcodes(stck, _sigscript)

                _pubkeyscript = inp["prevout"]["scriptpubkey_asm"].split()
                (stck, valid2) = loop_opcodes(stck, _pubkeyscript)

                if not valid1 or not valid2:
                    return False

                _redeemscript = inp["inner_redeemscript_asm"].split()
                if not process_scriptpubkey(_redeemscript) == dup_stck.pop():
                    print("False redeemScript - " + tx_filename)    
                    return False

            elif inp["prevout"]["scriptpubkey_type"] == "v0_p2wpkh":
                
                if len(data['vin']) > 1:
                    return False

                stck = Stack()

                if inp["scriptsig"] != "" or inp["scriptsig_asm"] != "" or len(inp["witness"]) != 2 or inp["prevout"]["scriptpubkey_asm"][0:20] != "OP_0 OP_PUSHBYTES_20" or process_scriptpubkey(inp["prevout"]["scriptpubkey_asm"].split()) != inp["prevout"]["scriptpubkey"]:
                    return False

                for i in inp["witness"]:
                    stck.push(i)

                std_script = f'OP_DUP OP_HASH160 OP_PUSHBYTES_20 {inp["prevout"]["scriptpubkey_asm"].split()[2]} OP_EQUALVERIFY OP_CHECKSIG'
                (stck, valid) = loop_opcodes(stck, std_script.split())

                if not valid:
                    return False
            
            elif inp["prevout"]["scriptpubkey_type"] == "v1_p2tr":
                pass
            
            elif inp["prevout"]["scriptpubkey_type"] == "v0_p2wsh":
                _pubkeyscript = inp["prevout"]["scriptpubkey_asm"].split()
                _pubkeyscripthash = process_scriptpubkey(_pubkeyscript)

                if _pubkeyscripthash != inp["prevout"]["scriptpubkey"] or _pubkeyscripthash[0:4] != "0020":
                    return False
            
            hex_seq = hex(inp["sequence"])

            if inp["prevout"]["value"] < 1:
                return False

            # improve this locktime constraint
            if hex_seq > '0xefffffff' and hex_seq != '0xffffffff':
                return False

            inp_amt += inp["prevout"]["value"]

        for outp in data["vout"]:
            _outscript = outp["scriptpubkey_asm"].split()
            valid1 = process_scriptpubkey(_outscript) == outp["scriptpubkey"]
            if not valid1:
                return False
            out_amt += outp["value"]

        if inp_amt < out_amt or inp_amt - out_amt < 500:
            return False

        try:
            wTxID(tx_filename)
            getTxID(tx_filename)
        except:
            return False

        return True

# a helper function to convert ASM list of operations into pubkey of the script
def process_scriptpubkey(oplist):
    key = ""
    opcodes = {
        'OP_0': '00',
        'OP_PUSHDATA1': '4c',
        'OP_PUSHDATA2': '4d',
        'OP_PUSHDATA4': '4e',
        'OP_1NEGATE': '4f',
        'OP_PUSHNUM_1': '51',
        'OP_PUSHNUM_2': '52',
        'OP_PUSHNUM_3': '53',
        'OP_PUSHNUM_4': '54',
        'OP_PUSHNUM_5': '55',
        'OP_PUSHNUM_6': '56',
        'OP_PUSHNUM_7': '57',
        'OP_PUSHNUM_8': '58',
        'OP_PUSHNUM_9': '59',
        'OP_PUSHNUM_10': '5a',
        'OP_PUSHNUM_11': '5b',
        'OP_PUSHNUM_12': '5c',
        'OP_PUSHNUM_13': '5d',
        'OP_PUSHNUM_14': '5e',
        'OP_PUSHNUM_15': '5f',
        'OP_PUSHNUM_16': '60',
        'OP_DUP': '76',
        'OP_HASH160': 'a9',
        'OP_EQUALVERIFY': '88',
        'OP_CHECKSIG': 'ac',
        'OP_VERIFY': '69',
        'OP_RETURN': '6a',
        'OP_EQUAL': '87',
        'OP_CHECKMULTISIG': 'ae',
        'OP_DROP': '75'
    #    'OP_PUSHNUM_1': ''
    }
    i = 0
    while i < len(oplist):
        if oplist[i] in opcodes.keys():
            key += opcodes[oplist[i]]
            if oplist[i][0:11] == "OP_PUSHDATA":
                key += oplist[i+1]
                i += 2
            else:
                i += 1
        elif oplist[i][0:12] == "OP_PUSHBYTES":
            temp = oplist[i].replace("OP_PUSHBYTES_", "")
            temp2 = str(hex(int(temp)))
            key += temp2.replace("0x","")
            key += oplist[i+1]
            i += 2
        else:
            print("OPCODE - Not Accounted for - " + oplist[i])
            i += 1
    return key

# the function which takes the stack and list of op codes as input, loops through each op and returns the stack and boolean whether the ops were valid or not
def loop_opcodes(stck, oplist):
    valid = True
    n = len(oplist)
    i = 0
    while i < n:
        _temp = process_opcode(stck, i, oplist)
        stck = _temp[0]
        i = _temp[1]
        if _temp[2] == False:
            valid = False
            break
    return (stck, valid)

# a helper function which processes an opcode at a time by taking inputs stack, index which is currently being processed of the opcode list
def process_opcode(stck, i, oplist):
    valid = True
    if oplist[i][0:12] == "OP_PUSHBYTES" or oplist[i][0:12] == "OP_PUSHDATA1" or oplist[i][0:12] == "OP_PUSHDATA2":
        stck.push(oplist[i+1])
        i += 2
    elif oplist[i] == "OP_DUP":
        val = stck.peek()
        stck.push(val)
        i += 1
    elif oplist[i] == "OP_HASH160":
        val = stck.pop()
        hash_object = hashlib.sha256(bytes.fromhex(val))
        hex_digest = hash_object.hexdigest()
        stck.push(_ripemd160(hex_digest))
        i += 1
    elif oplist[i] == "OP_EQUALVERIFY" or oplist[i] == "OP_EQUAL":
        val1 = stck.pop()
        val2 = stck.pop()
        if val1 != val2:
#            print(val1)
            valid = False
        i += 1
    elif oplist[i] == "OP_DROP":
        _val = stck.pop()
        i += 1
    elif oplist[i] == "OP_CHECKSIG":
        i += 1
    elif oplist[i] == "OP_0":
        stck.push(0)
        i += 1
    else:
        print(oplist[i])
        i += 1

    return [stck, i, valid]

# the function to construct a version 4 block header in a serialized form, takes merkle root as input
def block_header(merkle):
    header = ''
    version = 4
    previous_block = '0000b46885788719441442d10597f8d4bb16cb92fdaf918e92d062faf68b8018'
    difficulty = '0000ffff00000000000000000000000000000000000000000000000000000000'
    header += version.to_bytes(4, byteorder='little').hex()
    header += reverse_hex_string_bytearray(previous_block)
    header += merkle
    # timestamp
    header += get_timestamp()
    # block difficulty in Little Endian
    header += 'ffff001f'
    for i in range(0, 2**32):
        temp = header
        temp2 = i.to_bytes(4, byteorder='little').hex()
        temp += temp2
        if int(reverse_hex_string_bytearray(double_hash(temp)), 16) < int(difficulty, 16):
            return temp
    
# the function which constrtuct a serialized coinbase transaction, taking input of witness root
def coinbase_tx(witness_root):
    raw = ''
    # includes version in Little Endian, Input Count = 01 & Input 0 as 0 address and vout as highest value
    raw += '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff'
    # pushing block height and <3 as arbitrary data in scriptpubkey
    scriptpub = process_scriptpubkey(['OP_PUSHBYTES_3', 'ffffff', 'OP_PUSHBYTES_2', '3c33'])
    raw += f"{int(len(scriptpub) / 2):02x}"
    raw += scriptpub
    # setting sequence as 0
    raw += 'ffffffff'
    # output count as 2 and amount as 6.5 BTC
    raw += '028036be2600000000'
    # a P2PKH ouput with size as 19 hex bytes and script with unlocking public key as 2c30a6aaac6d96687291475d7d52f4b469f665a6
    raw += '1976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac'
    # zero amount
    raw += '0000000000000000'
    # to do - add witness reserved value for correct commitment
    commit = double_hash(witness_root + '0000000000000000000000000000000000000000000000000000000000000000')
    # print(commit)
    witscript = process_scriptpubkey(['OP_RETURN', 'OP_PUSHBYTES_36', f"aa21a9ed{commit}"])
    raw += f"{int(len(witscript) / 2):02x}"
    raw += witscript
    # witness stack
    raw += '01200000000000000000000000000000000000000000000000000000000000000000'
    # setting locktime as 0
    raw += '00000000'
    
    return raw

# -------------------------------- the execution part of the main function --------------------------------

# creates an empty list of witness hashes
w_txs = []
# adds zero witness hash as the first entry which corresponds to the coinbase transaction
w_txs.append('0000000000000000000000000000000000000000000000000000000000000000')

# loop for adding witness hashes of valid transactions to the list
folder = "mempool"
for filename in os.listdir(folder):
    if verify_tx(filename):
        w_txs.append(wTxID(filename))

# reversing the byte order of the witness hashes
rev = []
for i in w_txs:
    rev.append(reverse_hex_string_bytearray(i))

# constructs the witness root from the witness hashes list
witness_root = merkleroot(rev)
# print(w_txs)
print("witness - " + witness_root)

# creating a raw coinbase tx
raw_coinbase = coinbase_tx(witness_root)

# reversing the byte order after creating the coinbase txid from the raw coinbase tx
coinbase_txid = reverse_hex_string_bytearray(double_hash(raw_coinbase))

# creating the merkle root and txlist by calling the mempool function
(merkle, tx_list) = mempool(coinbase_txid)

# constructing the block header
header = block_header(merkle)

# writing all the data to the output.txt file in the given format
with open('output.txt', 'w') as file:
    file.write(header + '\n')
    file.write(raw_coinbase + '\n')
    for tx in tx_list:
        file.write(str(tx) + '\n')


# ------------------------------------------------ Testing Codes Below ------------------------------------------------

# print(reverse_hex_string_bytearray(double_hash(coinbase)))
# print(wtx_list)

# reverse_wtxids = []
# w_txs = ['0000000000000000000000000000000000000000000000000000000000000000', '8700d546b39e1a0faf34c98067356206db50fdef24e2f70b431006c59d548ea2', 'c54bab5960d3a416c40464fa67af1ddeb63a2ce60a0b3c36f11896ef26cbcb87', 'e51de361009ef955f182922647622f9662d1a77ca87c4eb2fd7996b2fe0d7785']
# for i in w_txs:
#     reverse_wtxids.append(reverse_hex_string_bytearray(i))
# witness_root = merkleroot(reverse_wtxids)
# print(witness_root)
# print(double_hash(witness_root + '0000000000000000000000000000000000000000000000000000000000000000'))
# print(coinbase_tx())
#print(process_scriptpubkey(['OP_PUSHBYTES_3', '951a06', 'OP_PUSHBYTES_32', '8a2a554f422bd182ef4e7a91e206e3a88a4f1c15eb6ec1a77e890675a924bdc5']))
#print(verify_tx("0dd03993f8318d968b7b6fdf843682e9fd89258c186187688511243345c2009f.json"))
# with open(f"mempool/0a4ce1145b6485c086f277aa185ba799234204f6caddb4228ee42b7cc7ad279a.json", 'r') as f:
#     data = json.load(f)
# print(getTxID("0a4ce1145b6485c086f277aa185ba799234204f6caddb4228ee42b7cc7ad279a.json"))
# txids = [
#   "321c449ef1ee7f6d3602d043faaaa1a1b20b4cff23f22b6e6de366163a558756",
#   "220d82a59a4c4f92eb2d77cc5b5c9ae0166a4e811c87a6677938404b72ddf03e",
# ]

# print(verify_tx("ff7d9ab4df5c33f6a3e347cacb759eff28a48a9936e0103a439a92019d6c1899.json"))

# # Reverse byte order of TXIDs
# #txids = [txid[::-1] for txid in txids]

# result = merkleroot(txids)
# print(result)

# print(double_hash("dbee9a868a8caa2a1ddf683af1642a88dfb7ac7ce3ecb5d043586811a41fdbf2" + "0000000000000000000000000000000000000000000000000000000000000000"))

# print(getTxID("04f89b4a86c1041a6d72b7a328089a2b915b7f7a207041564b708a75bd1161b1.json"))
# print(wTxID("04f89b4a86c1041a6d72b7a328089a2b915b7f7a207041564b708a75bd1161b1.json"))

# def check_tx_type(tx_filename):
#     with open(f"mempool/{tx_filename}", 'r') as f:
#         temp = []

#         data = json.load(f)

#         for inp in data["vin"]:
#             temp.append(inp["prevout"]["scriptpubkey_type"])

#         for outp in data["vout"]:
#             temp.append(outp["scriptpubkey_type"])

#         if "op_return" in temp:
#             print(tx_filename)

#         return set(temp)
    
# def tx_types():
#     out = set()
#     for filename in os.listdir("mempool"):
#         _temp = check_tx_type(filename)
#         for i in _temp:
#             out.add(i)
#     print(out)

# tx_types()