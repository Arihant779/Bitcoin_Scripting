import time
import hashlib
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from decimal import Decimal

# --- Modified function to compare vsize (virtual size) of segwit and legacy transactions ---
def compare_transaction_sizes(rpc_connection, legacy_txid, segwit_txid):
    """
    Compares the virtual size (vsize) of a legacy transaction and a segwit transaction.
    
    This version retrieves the transaction info with verbosity enabled to access 'vsize' or 'weight'.
    If neither is available, it falls back to computing the raw transaction size in bytes.
    Parameters:
      rpc_connection: Active RPC connection to bitcoind.
      legacy_txid: Transaction ID of the legacy transaction.
      segwit_txid: Transaction ID of the segwit transaction.
    """
    def get_vsize(txid):
        try:
            tx_info = rpc_connection.getrawtransaction(txid, True)
        except JSONRPCException as e:
            if hasattr(e, 'error') and e.error.get('code') == -5:
                tx_info = rpc_connection.gettransaction(txid)
            else:
                raise
        
        # If vsize is available and nonzero, use it.
        if "vsize" in tx_info and tx_info["vsize"]:
            return tx_info["vsize"]
        # If weight is available and nonzero, compute vsize = (weight + 3) // 4.
        if "weight" in tx_info and tx_info["weight"]:
            return (tx_info["weight"] + 3) // 4
        # Fallback: retrieve the raw hex and compute its byte length.
        try:
            raw_hex = rpc_connection.getrawtransaction(txid, False)
        except JSONRPCException as e:
            tx_info = rpc_connection.gettransaction(txid)
            raw_hex = tx_info.get("hex")
        return len(bytes.fromhex(raw_hex))
    
    try:
        vsize_legacy = get_vsize(legacy_txid)
        vsize_segwit = get_vsize(segwit_txid)
        print("\n--- Transaction Virtual Size (vsize) Comparison ---\n")
        print(f"Legacy transaction ({legacy_txid}) vsize: {vsize_legacy} bytes\n")
        print(f"SegWit transaction ({segwit_txid}) vsize: {vsize_segwit} bytes\n")
        if vsize_legacy > vsize_segwit:
            print(f"SegWit transaction is smaller by {vsize_legacy - vsize_segwit} bytes (vsize).\n")
        elif vsize_legacy < vsize_segwit:
            print(f"Legacy transaction is smaller by {vsize_segwit - vsize_legacy} bytes (vsize).\n")
        else:
            print("Both transactions have the same virtual size (vsize).\n")
    except Exception as e:
        print("Error comparing transaction sizes:", e)
        print()

# Setup RPC connection parameters
RPC_USER = "aaaaa"
RPC_PASSWORD = "bbbbb"
RPC_HOST = "127.0.0.1"
RPC_PORT = 18443  # Default port for regtest mode

# Connect to bitcoind RPC server
def connect_rpc():
    try:
        rpc_connection = AuthServiceProxy(f'http://{RPC_USER}:{RPC_PASSWORD}@{RPC_HOST}:{RPC_PORT}')
        print("Connected to RPC server\n")
        return rpc_connection
    except JSONRPCException as e:
        print(f"RPC connection failed: {e}\n")
        return None

# Generate blocks using a given address type (legacy or segwit)
def generate_blocks(rpc_connection, num_blocks=101, addr_type="legacy"):
    try:
        address = rpc_connection.getnewaddress("", addr_type)
        block_hashes = rpc_connection.generatetoaddress(num_blocks, address)
        print(f"Generated {num_blocks} blocks using {addr_type} address: {address}\n")
        return block_hashes
    except JSONRPCException as e:
        print(f"Error generating blocks: {e}\n")
        return []

# Fund an address and generate a confirming block (using provided address type)
def fund_address(rpc_connection, address, amount=1.0, addr_type="legacy"):
    try:
        print(f"Funding Address {address} with {amount} BTC...\n")
        fund_txid = rpc_connection.sendtoaddress(address, amount)
        print(f"Funded Address {address} with transaction ID: {fund_txid}\n")
        rpc_connection.generatetoaddress(1, rpc_connection.getnewaddress("", addr_type))
        print("Generated 1 block to confirm the transaction.\n")
        return fund_txid
    except JSONRPCException as e:
        print(f"Error funding Address {address}: {e}\n")
        return None

# Create a raw transaction (unsigned) for both legacy and segwit transactions.
def create_raw_transaction(rpc_connection, address_A, address_B, amount=0.0001):
    try:
        unspent = rpc_connection.listunspent(0, 9999999, [address_A])
        if not unspent:
            print("No unspent outputs found for address A.\n")
            return None

        total_input = sum(Decimal(u['amount']) for u in unspent)
        amount = Decimal(str(amount))
        fee = Decimal("0.00001")
        change = total_input - amount - fee
        if change < 0:
            print("Not enough funds to cover amount and fee.\n")
            return None

        tx_inputs = [{"txid": u['txid'], "vout": u['vout']} for u in unspent]
        tx_outputs = {
            address_B: str(amount),
            address_A: str(change) if change > 0 else None
        }
        tx_outputs = {k: v for k, v in tx_outputs.items() if v is not None}
        raw_tx = rpc_connection.createrawtransaction(tx_inputs, tx_outputs)
        print(f"Raw transaction created: {raw_tx}\n")
        return raw_tx
    except Exception as e:
        print(f"Error creating raw transaction: {e}\n")
        return None

# Compute HASH160: SHA256 then RIPEMD160
def hash160(b: bytes) -> str:
    sha256_digest = hashlib.sha256(b).digest()
    ripemd160_digest = hashlib.new('ripemd160', sha256_digest).hexdigest()
    return ripemd160_digest

########################################
# Verification for Legacy (P2PKH) inputs
########################################
def verify_legacy_transaction_inputs(rpc_connection, decoded_tx):
    if 'vin' not in decoded_tx:
        print("No inputs to verify.\n")
        return

    for vin in decoded_tx['vin']:
        prev_txid = vin['txid']
        prev_vout = vin['vout']
        try:
            # Retrieve previous transaction details (decoded)
            prev_tx = rpc_connection.getrawtransaction(prev_txid, True)
        except Exception as e:
            continue

        try:
            # Extract locking script from the previous transaction output
            locking_script = prev_tx['vout'][prev_vout]['scriptPubKey']
            asm_lock = locking_script.get('asm', '')
            tokens = asm_lock.split()
            # Expected format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
            if len(tokens) < 3:
                print("Unexpected locking script format in previous tx.\n")
                continue
            expected_hash = tokens[2]
        except Exception as e:
            print(f"Error extracting expected hash: {e}\n")
            continue

        # Legacy unlocking data is in scriptSig (asm)
        scriptSig = vin.get('scriptSig', {})
        asm_unlock = scriptSig.get('asm', '')
        parts = asm_unlock.split()
        if len(parts) < 2:
            print("Not enough parts in unlocking script for tx input from", prev_txid, "\n")
            continue
        # Assume last part is the public key.
        pubkey = parts[-1]
        try:
            pubkey_bytes = bytes.fromhex(pubkey)
        except Exception as e:
            print(f"Error converting pubkey to bytes: {e}\n")
            continue
        computed_hash = hash160(pubkey_bytes)
        print(f"Verifying legacy input spending {prev_txid}:{prev_vout}\n")
        print("  Expected HASH160 (from locking script):", expected_hash, "\n")
        print("  Computed HASH160 (from unlocking script):", computed_hash, "\n")
        if computed_hash == expected_hash:
            print("  Verification PASSED for this legacy input.\n")
        else:
            print("  Verification FAILED for this legacy input.\n")

########################################
# Verification for SegWit (P2WPKH) inputs
########################################
def verify_segwit_transaction_inputs(rpc_connection, decoded_tx):
    if 'vin' not in decoded_tx:
        print("No inputs to verify.\n")
        return

    for vin in decoded_tx['vin']:
        prev_txid = vin['txid']
        prev_vout = vin['vout']
        try:
            # Retrieve previous transaction details (decoded)
            prev_tx = rpc_connection.getrawtransaction(prev_txid, True)
        except Exception as e:
            continue

        try:
            # Extract locking script from previous output
            locking_script = prev_tx['vout'][prev_vout]['scriptPubKey']
            asm_lock = locking_script.get('asm', '')
            # For a native segwit P2WPKH, expected locking script asm is \"0 <pubKeyHash>\" 
            tokens = asm_lock.split()
            if len(tokens) < 2:
                print("Unexpected locking script format in previous tx.\n")
                continue
            expected_hash = tokens[1]  # This is the HASH160 (20-byte hash in hex)
        except Exception as e:
            print(f"Error extracting expected hash: {e}\n")
            continue

        # In segwit transactions, the unlocking data is stored in \"txinwitness\".
        witness = vin.get('txinwitness', [])
        if len(witness) < 2:
            print(f"Not enough witness elements in tx input from {prev_txid}\n")
            continue
        # For P2WPKH, witness[0] is the signature and witness[1] is the public key.
        pubkey = witness[1]
        try:
            pubkey_bytes = bytes.fromhex(pubkey)
        except Exception as e:
            print(f"Error converting witness pubkey to bytes: {e}\n")
            continue
        computed_hash = hash160(pubkey_bytes)
        print(f"Verifying segwit input spending {prev_txid}:{prev_vout}\n")
        print("  Expected HASH160 (from locking script):", expected_hash, "\n")
        print("  Computed HASH160 (from witness pubkey):", computed_hash, "\n")
        if computed_hash == expected_hash:
            print("  Verification PASSED for this segwit input.\n")
        else:
            print("  Verification FAILED for this segwit input.\n")

########################################
# Signing, broadcasting, decoding and verifying for Legacy transactions
########################################
def sign_send_and_verify_legacy(rpc_connection, raw_tx):
    try:
        signed_tx = rpc_connection.signrawtransactionwithwallet(raw_tx)
        if not signed_tx.get("complete"):
            print("Legacy transaction signing failed.\n")
            return None
        signed_hex = signed_tx['hex']
        txid = rpc_connection.sendrawtransaction(signed_hex)
        print(f"Legacy transaction broadcasted with TXID: {txid}\n")
        decoded = decode_raw_transaction(rpc_connection, signed_hex)
        if decoded:
            verify_legacy_transaction_inputs(rpc_connection, decoded)
        return txid
    except JSONRPCException as e:
        print(f"Error signing and sending legacy transaction: {e}\n")
        return None

########################################
# Signing, broadcasting, decoding and verifying for SegWit transactions
########################################
def sign_send_and_verify_segwit(rpc_connection, raw_tx):
    try:
        signed_tx = rpc_connection.signrawtransactionwithwallet(raw_tx)
        if not signed_tx.get("complete"):
            print("Segwit transaction signing failed.\n")
            return None
        signed_hex = signed_tx['hex']
        txid = rpc_connection.sendrawtransaction(signed_hex)
        print(f"Segwit transaction broadcasted with TXID: {txid}\n")
        decoded = decode_raw_transaction(rpc_connection, signed_hex)
        if decoded:
            verify_segwit_transaction_inputs(rpc_connection, decoded)
        return txid
    except JSONRPCException as e:
        print(f"Error signing and sending segwit transaction: {e}\n")
        return None

# Decode a transaction from raw hex
def decode_raw_transaction(rpc_connection, raw_tx):
    try:
        decoded_tx = rpc_connection.decoderawtransaction(raw_tx)
        print("Decoded Transaction:", decoded_tx, "\n")
        return decoded_tx
    except JSONRPCException as e:
        print(f"Error decoding raw transaction: {e}\n")
        return None

########################################
# Main function - Part 1: Legacy Transactions
########################################
def main():
    rpc_connection = connect_rpc()
    if not rpc_connection:
        return

    print("\n--- Legacy Transactions ---\n")
    # Generate blocks and addresses for legacy transactions
    generate_blocks(rpc_connection, 101, "legacy")
    legacy_A = rpc_connection.getnewaddress("", "legacy")
    legacy_B = rpc_connection.getnewaddress("", "legacy")
    legacy_C = rpc_connection.getnewaddress("", "legacy")
    print(f"Legacy Addresses:\nA: {legacy_A}\nB: {legacy_B}\nC: {legacy_C}\n")

    fund_txid = fund_address(rpc_connection, legacy_A, 0.01, "legacy")
    if not fund_txid:
        return

    txid_A_to_B = None
    raw_tx_A_to_B = create_raw_transaction(rpc_connection, legacy_A, legacy_B, 0.0001)
    if raw_tx_A_to_B:
        print("\n--- Processing Legacy Transaction from A to B ---\n")
        txid_A_to_B = sign_send_and_verify_legacy(rpc_connection, raw_tx_A_to_B)
    
    time.sleep(2)  # wait for confirmation

    # List unspent outputs for legacy address B (should include the UTXO from A to B)
    print("\n--- Listing UTXOs for Legacy Address B ---\n")
    utxos_B = rpc_connection.listunspent(0, 9999999, [legacy_B])
    for utxo in utxos_B:
        print("UTXO txid:", utxo["txid"], "vout:", utxo["vout"], "amount:", utxo["amount"])
    print()  # extra line for spacing

    raw_tx_B_to_C = create_raw_transaction(rpc_connection, legacy_B, legacy_C, 0.00005)
    if raw_tx_B_to_C:
        print("\n--- Processing Legacy Transaction from B to C ---\n")
        sign_send_and_verify_legacy(rpc_connection, raw_tx_B_to_C)

if __name__ == "__main__":
    main()
