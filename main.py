import os
import json
import hashlib

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

def serializeTransaction(data):
    raw = ''
    raw += data['version'].to_bytes(4, byteorder='little').hex()
    return raw


def mempool():
    inval_txs = 0
    val_txs = 0
    folder = "mempool"
    for filename in os.listdir(folder):
        if verify_tx(filename):
            val_txs += 1
        else:
            inval_txs += 1
    print(f"Valid Transactions : {val_txs}")
    print(f"Invalid Transactions : {inval_txs}")

def verify_tx(tx_filename):
    with open(f"mempool/{tx_filename}", 'r') as f:
#        valid = False

        data = json.load(f)

        inp_amt = 0
        out_amt = 0

        for inp in data["vin"]:

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
                
            else:
                return False
            
            hex_seq = hex(inp["sequence"])

            if hex_seq > '0xefffffff' and hex_seq != '0xffffffff':
                return False

            inp_amt += inp["prevout"]["value"]

        for outp in data["vout"]:
            _outscript = outp["scriptpubkey_asm"].split()
            valid1 = process_scriptpubkey(_outscript) == outp["scriptpubkey"]
            if not valid1:
                return False
            out_amt += outp["value"]

        if inp_amt < out_amt:
            return False
        
        return serializeTransaction(data)

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

def process_opcode(stck, i, oplist):
    valid = True
    if oplist[i][0:12] == "OP_PUSHBYTES":
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
        hash_object = hashlib.new('ripemd160')
        hash_object.update(bytes.fromhex(hex_digest))
        hex_digest = hash_object.hexdigest()
        stck.push(hex_digest)
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
    else:
#        print(oplist[i])
        i += 1

    return [stck, i, valid]

#mempool()
#print(verify_tx("0dd03993f8318d968b7b6fdf843682e9fd89258c186187688511243345c2009f.json"))
# print(verify_tx("fef2b7b6c156c891672141dd89032ae8cddee0562ad2d376b9b423c26d870682.json"))

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