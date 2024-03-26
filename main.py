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


def check_tx_type(tx_filename):
    with open(f"mempool/{tx_filename}", 'r') as f:
        temp = []

        data = json.load(f)

        for inp in data["vin"]:
            temp.append(inp["prevout"]["scriptpubkey_type"])

        for outp in data["vout"]:
            temp.append(outp["scriptpubkey_type"])

        if "op_return" in temp:
            print(tx_filename)

        return set(temp)
    
def tx_types():
    out = set()
    for filename in os.listdir("mempool"):
        _temp = check_tx_type(filename)
        for i in _temp:
            out.add(i)
    print(out)

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
        valid = False

        data = json.load(f)

        inp_amt = 0
        out_amt = 0

        for inp in data["vin"]:

            if inp["prevout"]["scriptpubkey_type"] == "p2pkh":
                stck = Stack()

                _sigscript = inp["scriptsig_asm"].split()
                (stck, valid) = loop_opcodes(stck, _sigscript)

                _pubkeyscript = inp["prevout"]["scriptpubkey_asm"].split()
                (stck, valid) = loop_opcodes(stck, _pubkeyscript)

                if valid == True:
                    pass

            elif inp["prevout"]["scriptpubkey_type"] == "p2sh":
                stck = Stack()

                _sigscript = inp["scriptsig_asm"].split()
                (stck, valid) = loop_opcodes(stck, _sigscript)

                _pubkeyscript = inp["prevout"]["scriptpubkey_asm"].split()
                (stck, valid) = loop_opcodes(stck, _pubkeyscript)

                check = stck.pop()
                if check == 1:
                    _redeemscript = inp["inner_redeemscript_asm"]
                    pass
                else:
                    valid = False

            inp_amt += inp["prevout"]["value"]

            if inp["prevout"]["scriptpubkey_type"] != "p2pkh":
                valid = False

        for outp in data["vout"]:
            out_amt += outp["value"]

        if data["locktime"] != 0 or inp_amt < out_amt:
            valid = False
        
        return valid

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
    elif oplist[i] == "OP_EQUALVERIFY":
        val1 = stck.pop()
        val2 = stck.pop()
        if val1 != val2:
            print(val1)
            valid = False
        i += 1
#    elif oplist[i] == "OP_0":

    else:
#        print(oplist[i])
        i += 1

    return [stck, i, valid]

# mempool()
# tx_types()