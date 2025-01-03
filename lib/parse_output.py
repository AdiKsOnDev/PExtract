import csv
import re

def parse_files(file_path):
    # Open and read the file
    with open(file_path, 'r') as f:
        file_data = f.read()

    # Regex patterns to capture various parts of the file
    file_pattern = re.compile(r'Analysing file --> (.*?)\n(.*?)\n={30,}', re.DOTALL)
    
    # Process each file's data
    files_data = []
    
    for file_match in file_pattern.findall(file_data):
        filename = file_match[0]
        content = file_match[1]

        # Extract DOS Header data (before 'Imported DLLs')
        dos_header = {}
        dos_header_pattern = re.compile(r'^[a-z]+: *[0-9a-fA-F]+$', re.MULTILINE)
        for line in dos_header_pattern.findall(content):
            key, value = line.split(":")
            dos_header[key.strip()] = value.strip()

        # Extract Imported DLLs and functions
        dlls = {}
        dll_pattern = re.compile(r'([a-zA-Z0-9.]+\.dll)\s+((?:\s+[a-zA-Z0-9_]+(?:\s+[a-zA-Z0-9_]+)*\s*)+)', re.MULTILINE)
        for match in dll_pattern.findall(content):
            dll_name = match[0]
            functions = match[1].strip().split('\n')
            dlls[dll_name] = ', '.join([fn.strip() for fn in functions])

        # Extract Sections
        sections = []
        section_pattern = re.compile(r'Section \d+: (\S+)', re.MULTILINE)
        for match in section_pattern.findall(content):
            sections.append(match)

        # Extract Optional Header data (after 'Imported DLLs')
        optional_header = {}
        optional_header_pattern = re.compile(r'^[a-zA-Z\s]+: *[0-9xX]+$', re.MULTILINE)
        for line in optional_header_pattern.findall(content):
            key, value = line.split(":")
            optional_header[key.strip()] = value.strip()

        # Add the data for the current file
        file_data = {
            'filename': filename,
            'dos_header': dos_header,
            'dlls': dlls,
            'sections': sections,
            'optional_header': optional_header
        }
        files_data.append(file_data)

    return files_data

def save_to_csv(output_path, all_files_data):
    # Collect all headers first
    headers = ['filename'] + \
              list(all_files_data[0]['dos_header'].keys()) + \
              list(all_files_data[0]['optional_header'].keys()) + \
              list(all_files_data[0]['dlls'].keys()) + ['sections']

    # Write to CSV file
    with open(output_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        
        # Write each file's data as a row in the CSV
        for file_data in all_files_data:
            row = [file_data['filename']] + \
                  list(file_data['dos_header'].values()) + \
                  list(file_data['optional_header'].values()) + \
                  list(file_data['dlls'].values()) + \
                  [', '.join(file_data['sections'])]
            writer.writerow(row)

if __name__ == '__main__':
    input_file = 'your_file.txt'  # Change to the path of your input file
    output_file = 'parsed_data.csv'  # Output CSV file name

    # Parse the file and extract relevant data
    all_files_data = parse_files(input_file)
    
    # Save the parsed data to a CSV file
    save_to_csv(output_file, all_files_data)
    print(f"Data saved to {output_file}")
