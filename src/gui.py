import os
import tkinter as tk
from tkinter import Listbox, Toplevel, filedialog, messagebox, Menu, Label, Button, Entry
from PIL import Image, ImageTk
import requests

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
        if url:
            headers = {"x-apikey": api_key}
            params = {'url': url}
            response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)

            if response.status_code == 200:
                # If the request was successful, submit the URL for scanning
                url_id = response.json()['data']['id']
                report_response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)

                if report_response.status_code == 200:
                    report = report_response.json()
                    messagebox.showinfo("URL Scan Result", str(report))
                else:
                    messagebox.showerror("Error", "Failed to get the report for the URL.")
            else:
                messagebox.showerror("Error", "Failed to submit the URL for scanning.")


    def quick_scan(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file, 'application/octet-stream')}
                headers = {'x-apikey': api_key}
                response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)

                if response.status_code == 200:
                    data = response.json()
                    analysis_id = data['data']['id']
                    messagebox.showinfo("Success", "File submitted successfully. Analysis ID: " + analysis_id)
                    # TODO: Poll for the completion of the analysis and retrieve the report
                else:
                    messagebox.showerror("Error", "An error occurred: " + response.text)

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
        if not file_path:  # If the user cancelled the dialog, file_path will be ''
            return  # Exit the method if no file was selected

        # If a file was selected, proceed to scan it
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': (file_path, file_to_scan, 'application/octet-stream')}
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
        messagebox.showinfo("About", "AIM Antivirus\nVersion 1.0")

def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
