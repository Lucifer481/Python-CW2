import os
import tkinter as tk
from tkinter import Listbox, filedialog, messagebox, Menu, Label, Button, Entry, Toplevel, Text, Scrollbar
from PIL import Image, ImageTk
import requests
import time
import json
import random
import threading

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
        url = self.url_entry.get().strip()  # Because even URLs need to look sharp
        if not url:
            messagebox.showinfo("Info", "You gotta give me something to work with here. Enter a URL.")
            return

    def perform_url_scan():
        try:
            headers = {"x-apikey": api_key}
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', headers=headers, data={'url': url})
            
            if response.status_code == 200:
                scan_id = response.json().get('scan_id')
                report_url = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={scan_id}'

                # Let's give it a moment to breathe, think, and analyze.
                time.sleep(15)  # Adjust based on your pace
                
                report_response = requests.get(report_url)
                if report_response.status_code == 200:
                    report = report_response.json()
                    detections = report.get('positives', 0)
                    total = report.get('total', 0)
                    message = f"Finished scanning the digital horizon. Found {detections} potential issues out of {total} checkpoints."
                    messagebox.showinfo("URL Scan Tale", message)
                else:
                    messagebox.showerror("Oops", "Seems like I couldn't fetch the epic saga of this URL. Try again later?")
            else:
                messagebox.showerror("Whoa", "Couldn't even start the quest to scan this URL. Something's amiss.")
        except Exception as e:
            messagebox.showerror("Uh-oh", f"Stumbled upon a digital gremlin: {e}")

    threading.Thread(target=perform_url_scan).start()
                
               


    def quick_scan(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            messagebox.showinfo("Info", "No file selected.")
            return

        progress_window = Toplevel(self.master)
        progress_window.title("Quick Scan in Progress")

        progress_text = Text(progress_window, height=10, width=50)
        progress_text.pack()
        progress_text.insert(tk.END, "Initializing quick scan...\n")

        def update_progress():
            steps = ["Scanning file signatures...", "Analyzing file behavior...", "Comparing against virus database...",
                     "Finalizing scan results..."]
            for step in steps:
                time.sleep(random.randint(1, 3))  # Simulate scan time
                progress_text.insert(tk.END, step + "\n")
                progress_text.see(tk.END)  # Scroll to the bottom
                progress_window.update_idletasks()  # Force window update

            # Simulate scan result
            scan_result = random.choice(["No threats found.", "Threats detected!"])
            progress_text.insert(tk.END, f"Scan complete. {scan_result}\n")

            # Add a button to close the progress window or view details
            if "threats" in scan_result.lower():
                result_button = Button(progress_window, text="View Threats", command=lambda: self.display_report({"threat": "Malware XYZ"}))
            else:
                result_button = Button(progress_window, text="Finish", command=progress_window.destroy)
            result_button.pack(pady=10)

        # Run the update progress in a separate thread to keep the GUI responsive
        threading.Thread(target=update_progress).start()

    def display_report(self, report):
        report_window = Toplevel(self.master)
        report_window.title("Scan Report")
    
        report_text = Text(report_window, wrap=tk.WORD)
        report_text.pack(fill=tk.BOTH, expand=True)
    
    # Assuming 'report' is a dictionary containing the scan results
        formatted_report = json.dumps(report, indent=4)
        report_text.insert(tk.END, formatted_report)

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
