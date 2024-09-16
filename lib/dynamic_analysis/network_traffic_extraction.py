import os
import subprocess
import threading
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor


def analyse_pe_file(pe_file_path, filter_ip=None):
    def run_pe_file():
        try:
            print(f"Running {pe_file_path}...")
            subprocess.run(pe_file_path, shell=True)
        except Exception as e:
            print(f"Error running PE file {pe_file_path}: {e}")

    def monitor_network_traffic():
        print(f"Monitoring network traffic for {pe_file_path}...")

        # Packet handler to print summary of each captured packet
        def packet_callback(packet):
            if packet.haslayer(scapy.IP):
                ip_layer = packet.getlayer(scapy.IP)
                if filter_ip:
                    if ip_layer.src == filter_ip or ip_layer.dst == filter_ip:
                        print(
                            f"Packet for {pe_file_path}: {ip_layer.src} -> {ip_layer.dst}")
                else:
                    print(
                        f"Packet for {pe_file_path}: {ip_layer.src} -> {ip_layer.dst}")

        # Start sniffing on all interfaces for IP packets
        scapy.sniff(filter="ip", prn=packet_callback, store=0,
                    timeout=30)  # Timeout to stop after 30s

    # Create threads for running the PE file and monitoring network traffic
    pe_thread = threading.Thread(target=run_pe_file)
    network_thread = threading.Thread(target=monitor_network_traffic)

    # Start both threads
    network_thread.start()
    pe_thread.start()

    # Wait for both threads to finish
    pe_thread.join()
    network_thread.join()


def process_pe_files_in_directory(directory_path, filter_ip=None):
    # Get all files in the directory to analyse them later
    pe_files = [os.path.join(directory_path, f)
                for f in os.listdir(directory_path) if f.endswith(".exe")]

    # Use ThreadPoolExecutor to parallelize the processing of PE files
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        for pe_file in pe_files:
            # Submit each PE file for parallel execution and traffic monitoring
            executor.submit(analyse_pe_file, pe_file, filter_ip)


if __name__ == "__main__":
    # Directory containing PE files
    directory = ""

    filter_ip = None

    process_pe_files_in_directory(directory, filter_ip)
