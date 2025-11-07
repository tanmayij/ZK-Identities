import pandas as pd
import numpy as np
from faker import Faker
from datetime import datetime, timedelta
from tqdm import tqdm

fake = Faker()
np.random.seed(42)

def random_dob(min_age = 0, max_age = 100):
    """Generate a random date of birth given an age range."""
    today = datetime.today()
    start_date = today - timedelta(days=365 * max_age)
    end_date = today - timedelta(days=365 * min_age)
    random_date = fake.date_between(start_date=start_date, end_date=end_date)
    return random_date

def random_citizenship():
    """Randomly select a citizenship from a predefined list."""
    citizenships = ['USA', 'Canada', 'UK', 'Australia', 'Germany', 'France', 'India', 'China', 'Brazil', 'South Africa']
    return np.random.choice(citizenships, p=[0.2, 0.1, 0.15, 0.1, 0.1, 0.1, 0.1, 0.05, 0.05, 0.05]) 

def random_license_class():
    """Randomly select a license class from a predefined list."""
    license_classes = ["G", "G2", "M", "D", "Z"]
    return np.random.choice(license_classes, p=[0.1, 0.4, 0.3, 0.15, 0.05])

def random_status():
    """Randomly select a license status from a predefined list."""
    statuses = ["Valid", "Suspended", "Expired", "Cancelled"]
    return np.random.choice(statuses, p=[0.7, 0.1, 0.15, 0.05])

def random_issue_date():
    start = datetime(2000, 1, 1)
    end = datetime.today()
    delta = end - start
    random_days = np.random.randint(0, delta.days) #warning: not really random!
    return (start + timedelta(days=random_days)).date()

def generate_dataset(num_records = 10000):
    record = []
    for i in tqdm(range(1, num_records + 1)):
        first_name = fake.first_name()
        last_name = fake.last_name()
        dob = random_dob(16, 90)
        citizenship = random_citizenship()
        license_class = random_license_class()
        status = random_status()
        issue_date = random_issue_date()
        
        record.append({
            "ID": i,
            "First Name": first_name,
            "Last Name": last_name,
            "Date of Birth": dob,
            "Citizenship": citizenship,
            "License Class": license_class,
            "Status": status,
            "Issue Date": issue_date
        })
    df = pd.DataFrame(record)
    df.to_csv("synthetic_driver_license_data.csv", index=False)
    print(f"Dataset with {num_records} records generated and saved to 'synthetic_users.csv'.")

if __name__ == "__main__":
    generate_dataset(10000)
    
