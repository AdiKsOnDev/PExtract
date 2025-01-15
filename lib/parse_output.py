import csv
import re
import argparse

def parse_analysis_file(input_file, output_csv):
    data = []
    current_file_data = None
    all_metadata_keys = set()

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            line = line.strip()

            if "Analysing file -->" in line:
                if current_file_data:
                    data.append(current_file_data)

                current_file_data = {
                    "file_name": re.search(r'--> (.+)$', line).group(1),
                    "metadata": {},
                    "dlls": [],
                    "sections": []
                }

            elif current_file_data is not None:
                metadata_match = re.match(r'\[34m(.+?):\[0m\s+(.*)$', line)
                if metadata_match:
                    key, value = metadata_match.groups()
                    current_file_data["metadata"][key.strip()] = value.strip()
                    all_metadata_keys.add(key.strip())

                elif "Imported DLLs:" in line:
                    current_file_data["dlls"] = []
                elif line.startswith("[34m") and line.endswith("[0m"):
                    match = re.search(r'\[34m(.+?)\[0m', line)
                    if match:
                        dll_name = match.group(1)
                        current_file_data["dlls"].append({"name": dll_name, "functions": []})
                    else:
                        print(f"Warning: Could not parse DLL names from file: {current_file_data['file_name']}")
                    current_file_data["dlls"].append({"name": dll_name, "functions": []})
                elif current_file_data["dlls"] and not line.startswith("[34m"):
                    current_file_data["dlls"][-1]["functions"].append(line.strip())

                section_match = re.match(r'Section (\d+): (.+)$', line)
                if section_match:
                    section_num, section_name = section_match.groups()
                    current_file_data["sections"].append(section_name.strip())

        if current_file_data:
            data.append(current_file_data)

    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)

        header = ["File Name"] + sorted(all_metadata_keys) + ["Imported DLLs", "Sections"]
        writer.writerow(header)

        for entry in data:
            row = [entry["file_name"]]
            row.extend([entry["metadata"].get(key, "") for key in sorted(all_metadata_keys)])
            dlls = "; ".join([f"{dll['name']} ({', '.join(dll['functions'])})" for dll in entry["dlls"]])
            sections = "; ".join(entry["sections"])
            row.extend([dlls, sections])
            writer.writerow(row)

    print(f"Data successfully written to {output_csv}")

# Command-line arguments parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse analysis logs and convert to CSV.")
    parser.add_argument("input_txt", type=str, help="Path to the input text file.")
    parser.add_argument("output_csv", type=str, help="Path to the output CSV file.")
    args = parser.parse_args()

    parse_analysis_file(args.input_txt, args.output_csv)
