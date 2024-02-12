import platform
import tkinter as tk
from tkinter import Listbox, Text, filedialog, messagebox, Toplevel, Label, Entry, Button
from PIL import Image, ImageTk
import os
import threading
import time
import psutil
import requests

# Assuming your .env setup and API key retrieval are already correctly implemented
api_key = os.getenv('VIRUSTOTAL_API_KEY')

class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title('Omega Antivirus')
        master.geometry('1024x768')

         # Define colors and load images
        self.dark_bg = '#333333'
        self.light_bg = '#F9FEFF'
        self.accent_color = '#4E9F3D'
        self.light_text = "#FFFFFF"
        self.quick_scan_img = ImageTk.PhotoImage(Image.open('img/quick_scan.png'))
        self.system_scan_img = ImageTk.PhotoImage(Image.open('img/full.png'))
        self.custom_scan_img = ImageTk.PhotoImage(Image.open('img/quar.png'))
        self.logo_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.privacy_icon_img = ImageTk.PhotoImage(Image.open('img/logo.png'))


        self.setup_sidebar()
        self.setup_content_area()

    def setup_sidebar(self):
        self.sidebar = tk.Frame(root, bg=self.dark_bg, width=200, height=768)
        self.sidebar.pack(side='left', fill='y', padx=20, pady=60)

        buttons_info = {
            "Dashboard": self.show_dashboard,
            "Protection": self.show_protection_options,
            "Privacy": self.show_privacy_dashboard,
            "About":self.show_about,
            "Setting": lambda: self.update_content("Set your preferences"),
            "Help": lambda: self.update_content("Get Help and Support")
        }


