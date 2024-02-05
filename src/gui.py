import tkinter as tk
from antivirus import Antivirus

class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.antivirus = Antivirus()
        self.setup_gui()

    def setup_gui(self):
        

    def scan_file(self):
       

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()
