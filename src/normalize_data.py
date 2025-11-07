#write a normalized parquet file to artifacts/normalized.parquet.
import pandas as pd
import pydantic
#Create a single source of truth for your CSV columns and types. 
from typing import Literal
from faker import Faker
fake =Faker()
class DriverLicenseRecord(pydantic.BaseModel):
    ID: int
    First_Name: str
    Last_Name: str
    Date_of_Birth: str  #ISO 8601 date string YYYY-MM-DD
    Citizenship: Literal['USA', 'Canada', 'UK', 'Australia', 'Germany', 'France', 'India', 'China', 'Brazil', 'South Africa']
    License_Class: Literal["G", "G2", "M", "D", "Z"]
    Status: Literal["Valid", "Suspended", "Expired", "Cancelled"]
    Issue_Date: str  #ISO 8601 date string YYYY-MM-DD

def normalize_data(input_csv: str, output_parquet: str):
    df = pd.read_csv(input_csv)
    records = []
    quarantine = []
    
    for idx, row in df.iterrows():
        try:
            record = DriverLicenseRecord(
                ID = int(row["ID"]),
                First_Name = row["First Name"].strip().title(),
                Last_Name = row["Last Name"].strip().title(),
                Date_of_Birth = pd.to_datetime(row["Date of Birth"]).strftime("%Y-%m-%d"),
                Citizenship = row["Citizenship"].strip(),  
                License_Class = row["License Class"].strip().upper(),
                Status = row["Status"].strip().title(),  #title case: "Valid" not "VALID"
                Issue_Date = pd.to_datetime(row["Issue Date"]).strftime("%Y-%m-%d")
            )
            records.append(record.model_dump()) 
        except Exception as e:
            print(f"Row {idx} failed validation: {e}")
            quarantine.append({**row.to_dict(), "error": str(e)})
    
    # write valid records
    normalized_df = pd.DataFrame(records)
    normalized_df.to_parquet(output_parquet, index=False)
    print(f"Normalized data written to {output_parquet} ({len(records)} valid rows)")
    
    #write quarantine if any
    if quarantine:
        quarantine_df = pd.DataFrame(quarantine)
        quarantine_path = output_parquet.replace(".parquet", "_quarantine.csv")
        quarantine_df.to_csv(quarantine_path, index=False)
        print(f"{len(quarantine)} invalid rows written to {quarantine_path}")

if __name__ == "__main__":
    normalize_data("data/synthetic_driver_license_data.csv", "artifacts/normalized.parquet")