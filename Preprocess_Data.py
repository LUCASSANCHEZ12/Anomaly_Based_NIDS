from pandas import read_csv, DataFrame, concat
from dotenv import load_dotenv
import os

# Read from environment variables
load_dotenv()
absolute_path = os.getenv("DATASET_PATH")

def concat_datasets(file_paths):
    datasets = DataFrame()
    # Concat all the datasets
    for file_path in file_paths:
        try:
            data = read_csv(file_path, encoding='utf-8')
            datasets = concat([datasets, data], ignore_index=True)
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    # Drop some columns
    # •	Timestamp 
    # •	Fwd Bytes/Bulk, Fwd Packets/Bulk, Bwd Bytes/Bulk, Bwd Packets/Bulk 
    # •	Subflow Fwd Packets, Subflow Bwd Packets, Subflow Fwd Bytes, Subflow Bwd Bytes
    # •	Fwd Header Length.1
    columns_to_drop = [
        ' Timestamp',
        ' Fwd Header Length.1',
        'Fwd Avg Bytes/Bulk',
        ' Fwd Avg Packets/Bulk',
        ' Fwd Avg Bulk Rate',
        ' Bwd Avg Bytes/Bulk',
        ' Bwd Avg Packets/Bulk',
        'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets',
        ' Subflow Fwd Bytes',
        ' Subflow Bwd Packets',
        ' Subflow Bwd Bytes'
    ]
    print(f"Concatenated dataset shape: {datasets.shape}")
    datasets = datasets.drop(columns=columns_to_drop, errors='ignore')
    # Convert to csv
    datasets.to_csv("./Complete_dataset.csv", index=False)
    print(f"Final dataset shape after dropping columns: {datasets.shape}")
    
    # Statistics
    total_rows = datasets.shape[0]
    count_benign = datasets[datasets[' Label'] == 'BENIGN'].shape[0]
    count_attack = datasets[datasets[' Label'] != 'BENIGN'].shape[0]

    print(f"Total rows across all datasets: {total_rows}")
    print(f"Total benign instances: {count_benign}")
    print(f"Total attack instances: {count_attack}")
    print(f"Percentage of benign instances: {count_benign / total_rows * 100:.2f}%")
    print(f"Percentage of attack instances: {count_attack / total_rows * 100:.2f}%")

    return datasets

# Read datasets from specified file paths
file_paths = [
    f"{absolute_path}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    f"{absolute_path}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    f"{absolute_path}/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    f"{absolute_path}/Monday-WorkingHours.pcap_ISCX.csv",
    f"{absolute_path}/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    f"{absolute_path}/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    f"{absolute_path}/Tuesday-WorkingHours.pcap_ISCX.csv",
    f"{absolute_path}/Wednesday-workingHours.pcap_ISCX.csv",
]

"""
Columns of the dataset
------------------------------------------------------------------------------------------------------------------
Feature Name				
'Flow ID'
' Source IP'
' Source Port'
' Destination IP'
' Destination Port'
' Protocol'
' Timestamp'
' Flow Duration'
' Total Fwd Packets'
' Total Backward Packets'
'Total Length of Fwd Packets'
' Total Length of Bwd Packets'
' Fwd Packet Length Max'
' Fwd Packet Length Min'
' Fwd Packet Length Mean'
' Fwd Packet Length Std'
'Bwd Packet Length Max'
' Bwd Packet Length Min'
' Bwd Packet Length Mean'
' Bwd Packet Length Std'
'Flow Bytes/s'
' Flow Packets/s'
' Flow IAT Mean'
' Flow IAT Std'
' Flow IAT Max'
' Flow IAT Min'
'Fwd IAT Total'
' Fwd IAT Mean'
' Fwd IAT Std'
' Fwd IAT Max'
' Fwd IAT Min'
'Bwd IAT Total'
' Bwd IAT Mean'
' Bwd IAT Std'
' Bwd IAT Max'
' Bwd IAT Min'
'Fwd PSH Flags'
' Bwd PSH Flags'
' Fwd URG Flags'
' Bwd URG Flags'
' Fwd Header Length'
' Bwd Header Length'
'Fwd Packets/s'
' Bwd Packets/s'
' Min Packet Length'
' Max Packet Length'
' Packet Length Mean'
' Packet Length Std'
' Packet Length Variance'
'FIN Flag Count'
' SYN Flag Count'
' RST Flag Count'
' PSH Flag Count'
' ACK Flag Count'
' URG Flag Count'
' CWE Flag Count'
' ECE Flag Count'
' Down/Up Ratio'
' Average Packet Size'
' Avg Fwd Segment Size'
' Avg Bwd Segment Size'
' Fwd Header Length.1'
'Fwd Avg Bytes/Bulk'
' Fwd Avg Packets/Bulk'
' Fwd Avg Bulk Rate'
' Bwd Avg Bytes/Bulk'
' Bwd Avg Packets/Bulk'
'Bwd Avg Bulk Rate'
'Subflow Fwd Packets'
' Subflow Fwd Bytes'
' Subflow Bwd Packets'
' Subflow Bwd Bytes'
'Init_Win_bytes_forward'
' Init_Win_bytes_backward'
' act_data_pkt_fwd'
' min_seg_size_forward'
'Active Mean'
' Active Std'
' Active Max'
' Active Min'
'Idle Mean'
' Idle Std'
' Idle Max'
' Idle Min'
' Label'
------------------------------------------------------------------------------------------------------------------
"""
# Use dataframe
df = concat_datasets(file_paths)