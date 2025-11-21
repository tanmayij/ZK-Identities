import os
import cryptography
from pymerkle import MerkleTree
import secrets
import pandas as pd

expected_cols = ["id", "dob", "citizenship", "license_class", "status", "issue_date"]
df = pd.read_csv("data/synthetic_driver_license_data.csv")
assert all(col in df.columns.str.lower() for col in expected_cols), "Dataframe does not contain the expected columns."

#for later -- normaliz the data (or make skewed workloads)
def normalize_record(record):
    record["dob"] = pd.to_datetime(record["dob"]).strftime("%Y-%m-%d")
    record["citizenship"] = record["citizenship"].strip().upper()
    record["license_class"] = record["license_class"].strip().upper()
    record["status"] = record["status"].strip().upper()
    record["issue_date"] = pd.to_datetime(record["issue_date"]).strftime("%Y-%m-%d")
    return record

#function to convert all attributes to strings 
def record_to_String(record):
    for col in df.columns:
        record[col] = df[col].astype(str)
    return record

#for later -- shuffle records 

def validate_and_snapshot(df):
    df.to_csv("data/normalized_driver_license_data.csv", index=False)
    print("Dataframe validated and snapshot saved.")

#random salt mode
def random_salt():
    return secrets.randbelow(1 << 256)

#deterministic salt mode 
def deterministic_salt(record_id):
    bytes = record_id.to_bytes((record_id.bit_length() + 7) // 8, byteorder='big')
    #prepare a master seed and include epochal data
    master_seed = b"master_seed_for_deterministic_salt"
    combined = master_seed + bytes
    hash = cryptography.hazmat.primitives.hashes.Hash(cryptography.hazmat.primitives.hashes.SHA256())
    hash.update(combined)
    digest = hash.finalize()
    #epoch time component
    epoch_time = int(os.environ.get("EPOCH_TIME", "0"))
    epoch_bytes = epoch_time.to_bytes((epoch_time.bit_length() + 7) //
                            8, byteorder='big')
    final_combined = digest + epoch_bytes
    final_hash = cryptography.hazmat.primitives.hashes.Hash(cryptography.hazmat.primitives.hashes.SHA256())
    final_hash.update(final_combined)
    final_digest = final_hash.finalize()
    return int.from_bytes(final_digest, byteorder='big')

#store all salts for each attribute in each record in a dictionary
def salts_dict(df):
    salts = {}
    for index, row in df.iterrows():
        record_id = row["ID"]
        salts[record_id] = {}
        for col in expected_cols[1:]:  # Skip 'id' column
            salts[record_id][col] = deterministic_salt(record_id)
    return salts

#serialize attribute values
def serialize_record(record):
    serialized = ""
    for col in expected_cols:
        serialized += str(record[col]) + "|"
    return serialized[:-1]  # Remove trailing '|'

#make attribute commitments
# def commit_attributes(record, salts):
    






