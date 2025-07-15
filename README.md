Dual-Factor Worm Detection Based on Signature & Anomaly

Overview:
This project is a hybrid worm detection system that integrates both signature-based and anomaly-based detection methods to identify internet worms in real-time. It uses PCAP file analysis for signature detection and machine learning models to detect anomalous behaviors in network traffic, providing a robust defense against both known and unknown threats.

Objective:
To design and implement a dual-factor worm detection system that effectively detects malicious activities using:
- Signature matching from PCAP files.
- Anomaly detection using machine learning classification.

Technologies & Libraries:
- Language: Python
- GUI: Tkinter
- Libraries:
  - Scapy (PCAP analysis)
  - Pandas, NumPy (Data processing)
  - Scikit-learn (Machine Learning: Decision Tree, Random Forest, Naive Bayes)
  - Matplotlib (Graph plotting)

How It Works:
- Upload PCAP File → Signature-Based Detection runs using Scapy.
- Upload IDS Dataset → Trains ML models for anomaly-based detection.
- Predict → Classifies network activities and displays alerts for detected worms.
- View Results → Accuracy, Precision, Recall, F1-score are visualized.

Project Structure:
- InternetWormDetection.py          - Main GUI application
- SignatureBasedDetection.py       - Signature detection logic
- AnomalyDataset/                  - CSV datasets for ML
- PCAP_Signatures/                 - Sample PCAP files
- IDSAttackDataset/                - Testing data
- table.html                       - Dynamic output table
- README.txt

Features:
- Dual detection logic (Signature + ML Anomaly)
- Real-time packet analysis using Scapy
- GUI for interactive use
- Graphical and tabular result comparison


Contact:
For queries, contact ksaikiran950@gmail.com

