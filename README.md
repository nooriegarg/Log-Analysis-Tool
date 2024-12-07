# Log-Analysis-Tool
This repository contains a Python script to analyze server log files, extract useful information, and detect suspicious activity. The tool processes a sample log file and saves the analysis results to a CSV file.

# Features
- Count the number of requests made by each IP address.
- Identify the most frequently accessed endpoints.
- Detect suspicious activity, such as multiple failed login attempts.

# How It Works
1. Input: The script takes a log file as input (e.g., sample.log).
2. Processing:
  - Extracts important fields like IP address, endpoint, status, and messages using regex.
  - Filters logs based on status codes or error messages like "Invalid credentials."
3. Output: Results are saved to a CSV file (log_analysis_results.csv) with detailed analysis.

# Requirements
Python 3.8 or higher\n
Pandas library

# File Structure
├── data
│   └── sample.log               # Example log file
├── results
│   └── log_analysis_results.csv # Analysis results
├── scripts
│   └── log_analysis.py          # Python script for log analysis
├── README.md                    # Project description

# How to Run the Script
Clone this repository to your local machine:
  git clone https://github.com/your-username/Log-Analysis-Tool.git
  cd Log-Analysis-Tool
Place your log file in the data/ directory if you want to analyze a different file.

# Run the Python script:
  python scripts/log_analysis.py
Check the results/ directory for the output CSV file.

# Output
The script generates a CSV file with the following information:
  - Requests per IP: Counts the number of requests made by each IP address.
  - Most Accessed Endpoint: Identifies the endpoint with the highest access count.
 - Suspicious Activity: Detects IPs with failed login attempts exceeding a defined threshold.
   
# Customizations
You can modify the threshold for detecting suspicious activity by changing the SUSPICIOUS_THRESHOLD value in the script:
  SUSPICIOUS_THRESHOLD = 10
  
# Example Log Entry
Here’s an example of a log line the script can process:

 127.0.0.1 - - [10/Dec/2024:12:45:33 +0000] "GET /index.html HTTP/1.1" 200 1043
 
# Contact
If you have any questions or feedback, feel free to reach out via this repository's issue tracker.
