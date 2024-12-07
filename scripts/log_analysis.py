import re
import pandas as pd

# Define the log file and output csv file paths
log_file = "sample.log"
output_file = "log_analysis_results.csv"

SUSPICIOUS_THRESHOLD = 10   # Threshold for suspicious activity


def parse_logs(file_path):
    """
    Parses the log file using a regex pattern to extract relevant fields.
    
    Args: 
        file_path (str) : Path to the log file.
    
    Returns:
       df (pd.DataFrame) : A DataFrame containing parsed log details.
    """

    # Regex pattern to extract log details
    # Explanation:
    # (\S+)                 : Matches the IP address (any non-whitespace characters until the first space)
    # \S+ \S+               : Skips over two fields we don't need (user identity and user ID)
    # \[([\w:/]+\s[+\-]\d{4})\] : Matches the timestamp in square brackets (e.g., [10/Dec/2024:12:45:33 +0000])
    # "\S+ (\S+) \S+"       : Matches the HTTP method and requested endpoint (e.g., GET /index.html HTTP/1.1)
    # (\d{3})               : Matches the status code (e.g., 200, 404)
    # \d+                   : Skips the size of the response
    # \s*(".*")*            : Optionally matches the message in quotes (e.g., "Invalid credentials")

    log_pattern  = re.compile(r'(\S+) \S+ \S+ \[[\w:/]+\s[+\-]\d{4}\] "\S+ (\S+) \S+" (\d{3}) \d+\s*(".*")*')
    parsed_logs = []

    try:
        # Open the file and process each line
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    parsed_logs.append(match.groups())
                else:
                    print(f"Line did not match: {line}")
                    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return pd.DataFrame()  # Return an empty DataFrame if the file is missing
    
    

    # Convert the parsed data into a DataFrame
    columns = ['IP', 'Endpoint','Status','Message']
    df = pd.DataFrame(parsed_logs, columns=columns)

    # Convert the Status column to numeric for easier filtering
    df['Status'] = pd.to_numeric(df['Status'], errors='coerce')
    return df


def analyze_requests_per_ip(df):
    """
    Counts the number of requests made by each IP address.
    
    Args:
        df (pd.DataFrame): The DataFrame containing log data.
    
    Returns:
        sorted_ip_counts (dict) : A sorted dictionary of IP addresses and their request counts.
    """
   
    ip_counts = df['IP'].value_counts()
    sorted_ip_counts = dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True))

    print(f"{'IP Address':<20}{'Request Count':<10}")
    for ip, count in sorted_ip_counts.items():
        print(f"{ip:<20}{count:<10}")

    return sorted_ip_counts


def find_most_accessed_endpoint(df):
    """
    Identifies the most frequently accessed endpoint.
    
    Args:
        df (pd.DataFrame): The DataFrame containing log data.
    
    Returns:
        most_accessed (tuple) : The most accessed endpoint and its access count.
    """

    endpoint_counts = df['Endpoint'].value_counts()
    most_accessed = endpoint_counts.idxmax(), endpoint_counts.max()

    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    return most_accessed


def detect_suspicious_activity(df):
    """
    Detects suspicious activity based on failed login attempts.
    
    Args:
        df (pd.DataFrame): The DataFrame containing log data.
    
    Returns:
        dict: A sorted dictionary of suspicious IP addresses and their failed attempt counts.
    """

    # Filter for 401 status codes or "Invalid credentials" messages
    suspicious_logs = df[(df['Status'] == 401)  | (df['Message']=="Invalid credentials")]
    
    suspicious_counts = suspicious_logs['IP'].value_counts()
    sorted_suspicious_counts = dict(sorted(suspicious_counts.items(), key=lambda item: item[1], reverse=True))

    flag = False

    print(f"\nSuspicious Activity Detected:\n{'IP Address':<20}{'Failed Login Attempts':<20}")
    for ip, count in sorted_suspicious_counts.items():
        if count > SUSPICIOUS_THRESHOLD:
            flag = True
            print(f"{ip:<20}{count:<20}")

    if not flag:
        print(f"{"-":<20}{"-":<20}")   #prints "-" incase of no suspicious activity above threshold

    return sorted_suspicious_counts


def save_results_to_csv(output_file, ip_counts, most_accessed, suspicious_counts):
    """
    Saves the analysis results to a CSV file.
    
    Args:
        output_file (str): Path to the output CSV file.
        ip_counts (dict): Requests per IP data.
        most_accessed (tuple): Most accessed endpoint data.
        suspicious_counts (dict): Suspicious activity data.
    """
    try:
        with open(output_file, 'w', newline='') as file:
            # Write Requests per IP section
            file.write("Requests per IP:\n")
            file.write("IP Address,Request Count\n")
            for ip, count in ip_counts.items():
                file.write(f"{ip},{count}\n")

            # Write Most Accessed Endpoint section
            file.write("\nMost Accessed Endpoint:\n")
            file.write("Endpoint,Access Count\n")
            file.write(f"{most_accessed[0]},{most_accessed[1]}\n")

            # Write Suspicious Activity section
            file.write("\nSuspicious Activity:\n")
            file.write("IP Address,Failed Login Attempts\n")

            flag = False

            for ip, count in suspicious_counts.items():
                if count > SUSPICIOUS_THRESHOLD:
                    flag = True
                    file.write(f"{ip},{count}\n")
            
            if not flag:
                file.write("-,-\n")  # writes "-" incase of no suspicious activity above threshold

        print(f"\nResults have been saved to {output_file}.")

    except Exception as e:
        print(f"Error while saving results: {e}")


def main():
    """
    Main function for log analysis
    """
    # Parse the logs into a DataFrame
    df = parse_logs(log_file)

    # Ensure DataFrame is not empty before proceeding
    if df.empty:
        print("No data to process. Exiting..")
        return

    # # Analyze requests per IP
    ip_counts = analyze_requests_per_ip(df)

    # # Find the most accessed endpoint
    most_accessed = find_most_accessed_endpoint(df)

    # # Detect suspicious activity
    suspicious_counts = detect_suspicious_activity(df)

    # # Save the results to a CSV file
    save_results_to_csv(output_file, ip_counts, most_accessed, suspicious_counts)


# Run the main function
if __name__ == "__main__":
    main()
