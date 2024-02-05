import tkinter as tk
from tkinter import filedialog, messagebox
from antivirus import scan_file

class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title("AIM Antivirus")

        # Label
        self.label = tk.Label(master, text="AIM Antivirus", font=("Arial", 24))
        self.label.pack(pady=10)

        # Scan Button
        self.scan_btn = tk.Button(master, text="Scan File", command=self.scan_file)
        self.scan_btn.pack(pady=5)

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            results = scan_file(file_path)
            message = f"Threat Level: {results['threat_level']}\nPositive Detections: {results['positive_detections']} / {results['total_engines']}\n\nDetailed Engine Results:\n{results['detailed_engine_results']}"
            messagebox.showinfo("Scan Results", message)

root = tk.Tk()
app = AntivirusGUI(root)
root.mainloop()
