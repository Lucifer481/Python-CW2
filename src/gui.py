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
        master.title('Antivirus')
        master.geometry('1024x768')

         # Define colors and load images
        self.dark_bg = '#0a0000'
        self.light_bg = '#fafafa'
        self.accent_color = '#61cf4a'
        self.light_text = "#FFFFFF"
        self.quick_scan_img = ImageTk.PhotoImage(Image.open('img/quick_scan.png'))
        self.system_scan_img = ImageTk.PhotoImage(Image.open('img/full.png'))
        self.custom_scan_img = ImageTk.PhotoImage(Image.open('img/quar.png'))
        self.logo_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.privacy_icon_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.about_logo_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.help_icon_img = ImageTk.PhotoImage(Image.open('img/logo.png'))


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

        for text, command in buttons_info.items():
            button = tk.Button(self.sidebar, text=text, fg=self.light_text, bg=self.dark_bg, bd=0, padx=20, pady=10, command=command)
            button.pack(fill="x")

    def setup_content_area(self):
        self.content = tk.Frame(root, bg=self.light_bg)
        self.content.pack(expand=True, fill='both')

    def show_dashboard(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        dashboard_frame = tk.Frame(self.content, bg=self.light_bg)
        dashboard_frame.pack(expand=True, fill='both')

        # Logo and Welcome Message
        logo_label = tk.Label(dashboard_frame, image=self.logo_img, bg=self.light_bg)
        logo_label.image = self.logo_img
        logo_label.pack(pady=20)

        welcome_label = tk.Label(dashboard_frame, text="Welcome to Omega Antivirus", bg=self.light_bg, font=("Helvetica", 20, "bold"), fg=self.accent_color)
        welcome_label.pack()

        # System Information
        system_info_label = tk.Label(dashboard_frame, text="System Information", bg=self.light_bg, font=("Helvetica", 16, "underline"), fg=self.accent_color)
        system_info_label.pack(pady=10)

        current_status_message = "Your PC is running smoothly. All systems are go!"
        status_message_label = tk.Label(dashboard_frame, text=current_status_message, bg=self.light_bg, font=("Helvetica", 16), fg=self.accent_color)
        status_message_label.pack()

        system_info = {
            "Operating System": platform.system(),
            "Processor": platform.processor(),
            "RAM": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
            "Storage": f"{psutil.disk_usage('/').total / (1024 ** 3):.2f} GB",
        }
        for key, value in system_info.items():
            info_label = tk.Label(dashboard_frame, text=f"{key}: {value}", bg=self.light_bg, font=("Helvetica", 12))
            info_label.pack()

        
        # Dynamic Status Indicator
        status_label = tk.Label(dashboard_frame, text="Current PC Status", bg=self.light_bg, font=("Helvetica", 16, "underline"), fg=self.accent_color)
        status_label.pack(pady=10)

        status_indicator = tk.Label(dashboard_frame, text="Stable", bg=self.light_bg, fg=self.accent_color, font=("Helvetica", 14, "bold"))
        status_indicator.pack()



