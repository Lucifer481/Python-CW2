import os
import tkinter as tk
from tkinter import Listbox, filedialog, messagebox, Menu, Label, Button, Entry, Toplevel, Text, Scrollbar
from PIL import Image, ImageTk
import requests
import time
import json
import random
import threading
from cli import achievements

# Load API key from environment variable
api_key = os.getenv('VIRUSTOTAL_API_KEY')

class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title("AIM Antivirus")

        # Background image
        self.bg_image = ImageTk.PhotoImage(Image.open("img/bg.jpg"))
        self.bg_label = Label(master, image=self.bg_image)
        self.bg_label.place(relwidth=1, relheight=1)

        # Logo
        self.logo_image = ImageTk.PhotoImage(Image.open("img/search.png"))
        self.logo_label = Label(master, image=self.logo_image, bg='white')
        self.logo_label.pack(pady=20)

        # URL Checker Entry
        self.url_entry = Entry(master, width=50)
        self.url_entry.pack(pady=10)

        # URL Checker Button
        self.url_check_button = Button(master, text="Check URL", command=self.scan_url)
        self.url_check_button.pack()

        # Quick Scan Button
        self.quick_scan_button = Button(master, text="Quick Scan", command=self.quick_scan)
        self.quick_scan_button.pack(pady=10)

        # Hash Id Button
        self.hash_id_button = Button(master, text="Hash Id", command=self.hash_id)
        self.hash_id_button.pack(pady=10)

        # Quarantine Button
        self.quarantine_button = Button(master, text="Quarantine", command=self.show_quarantine)
        self.quarantine_button.pack(pady=10)

        # Menu
        self.menu_bar = Menu(master)
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Open File...", command=self.open_file)
        self.file_menu.add_command(label="Exit", command=master.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.menu_bar.add_command(label="About", command=self.show_about)
        master.config(menu=self.menu_bar)

    def scan_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showinfo("Info", "Please enter a URL to check.")
            return

        def perform_url_scan():
            try:
                headers = {"x-apikey": api_key}
                params = {'url': url}
                response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)

                if response.status_code == 200:
                    url_id = response.json()['data']['id']
                    url_id_encoded = requests.utils.quote(url_id)
                    time.sleep(10)
                    
                    report_response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id_encoded}', headers=headers)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        self.display_url_report(report)
                    else:
                        messagebox.showerror("Error", "Failed to get the report for the URL. Please try again later.")
                else:
                    messagebox.showerror("Error", "Failed to submit the URL for scanning.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

        threading.Thread(target=perform_url_scan).start()

    def scan(self, directory_path):
        suspicious_extensions = ['.exe', '.js', '.bat', '.cmd', '.sh'] # Sample extension
        found_suspicious_files = []

        # Scan through the dir to find sispicious fiels
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in suspicious_extensions):
                    found_suspicious_files.append(os.path.join(root,file))

        
        # scan delay
        time.sleep(2)

        # Display scan report
        if found_suspicious_files:
            report_message = f"Scan Complete. Found {len(found_suspicious_files)} suspicious files."
            if tk.messagebox.askyesno("Scan Complete", f"{report_message}\nWould you like to see a detailed report?"):
                detailed_report = "\n".join(found_suspicious_files)
                self.show_detailed_report(detailed_report)

        else:
            tk.messagebox.showinfo("Scan Complete", "No suspicious files found!")

    def show_detailed_report(self, report):
    
    # Displaying the detailed report in a new window
        report_window = tk.Toplevel(self.master)
        report_window.title("Detailed Scan Report")
        text_area = tk.Text(report_window, wrap="word")
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, report)

    # Allow the text widget to be read-only
        text_area.configure(state="disabled")

    def quick_scan(self):
    # User selects the directory to scan
        directory_path = filedialog.askdirectory()
        if not directory_path:
            messagebox.showinfo("Quick Scan", "Scan cancelled, no directory selected.")
            return

    # Run the scan in a non-blocking way
        threading.Thread(target=lambda: self.scan(directory_path)).start()

            

    def hash_id(self):
        # Prompt the user to select a file
        file_path = filedialog.askopenfilename()
        if not file_path:
            # User cancelled the selection
            messagebox.showinfo("Hash ID", "No file selected.")
            return

        # Read the file content
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': (file_path, file_to_scan)}

            headers = {"x-apikey": api_key}
            response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

            if response.status_code == 200:
                # The file was submitted successfully
                data = response.json()
                analysis_id = data['data']['id']

                # Retrieve the analysis results
                report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                report_response = requests.get(report_url, headers=headers)

                if report_response.status_code == 200:
                    report = report_response.json()
                    # Show the result to the user
                    messagebox.showinfo("Hash Id Result", str(report))
                else:
                    messagebox.showerror("Hash ID", "Failed to get the scan report.")
            else:
                messagebox.showerror("Hash ID", "Failed to submit the file for scanning.")
    

    def show_quarantine(self):
        quarantine_window = Toplevel(self.master)
        quarantine_window.title("Quarantined Items")

        listbox = Listbox(quarantine_window)
        listbox.pack(fill="both", expand=True)

        # Just as an example, add some dummy items to the listbox
        listbox.insert("end", "malicious_file_1.exe")
        listbox.insert("end", "malicious_file_2.exe")

    def open_file(self):
        # Open the file dialog to let the user select a file
        file_path = filedialog.askopenfilename(title="Choose a file to scan")
        if not file_path:  # If the user canceled the dialog, file_path will be ''
            return  # Exit the method if no file was selected

        # If a file was selected, proceed to scan it
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': (os.path.basename(file_path), file_to_scan, 'application/octet-stream')}
            headers = {'x-apikey': api_key}

            # Send the file to the VirusTotal API for scanning
            response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

            # Check the response status code
            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                # Inform the user that the file has been submitted for scanning
                messagebox.showinfo("File Submitted", f"File {file_path} submitted for scanning. Analysis ID: {analysis_id}")
                # TODO: Implement logic to retrieve and display the scan report
            else:
                # If the API call failed, show an error message
                messagebox.showerror("Error", f"Failed to submit the file for scanning. Error code: {response.status_code}")

    def show_about(self):
        messagebox.showinfo("About", "Antivirus\nVersion 1.0")

def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
