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
        self.full_scan_img = ImageTk.PhotoImage(Image.open('img/full.png'))
        self.real_img = ImageTk.PhotoImage(Image.open('img/pro.png'))
        self.hash_img =ImageTk.PhotoImage(Image.open('img/hash.png'))
        self.quarantine_img = ImageTk.PhotoImage(Image.open('img/quar.png'))
        self.logo_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.privacy_icon_img = ImageTk.PhotoImage(Image.open('img/logo.png'))
        self.about_logo_img = ImageTk.PhotoImage(Image.open('img/about.png'))
        self.help_icon_img = ImageTk.PhotoImage(Image.open('img/help.png'))


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
    

    def update_content(self, text):
        for widget in self.content.winfo_children():
            widget.destroy()
        tk.Label(self.content, text=text, bg=self.light_bg, font=("Helvetica", 16)).pack(expand=True)

    def show_protection_options(self):
        for widget in self.content.winfo_children():
            widget.destroy()
        
        options_frame = tk.Frame(self.content, bg=self.light_bg)
        options_frame.pack(expand=True, fill='both')

        scan_options = [
            ("Quick Scan", self.quick_scan_img, "Scans critical areas where malware usually resides.", self.quick_scan),
            ("Advance Scan", self.full_scan_img, "Scans all your files and directories.", self.advance_scan),
            ("Real-time Protection", self.real_img, "Turn ON Real Time Protection", self.real_time_protection),
            ("Hash ID", self.hash_img, "Analysis The malware ID", self.hash_id),
            ("Quarantine", self.quarantine_img, "Show malware quarantine", self.show_quarantine)
        ]

        for option, img, desc, command in scan_options:
            self.create_scan_option(options_frame, option, img, desc, command)
    
    def show_privacy_dashboard(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        privacy_frame = tk.Frame(self.content, bg=self.light_bg)
        privacy_frame.pack(expand=True, fill='both')

        # Privacy Icon and Message
        privacy_icon_label = tk.Label(privacy_frame, image=self.privacy_icon_img, bg=self.light_bg)
        privacy_icon_label.image = self.privacy_icon_img
        privacy_icon_label.pack(pady=20)

        privacy_message = "Your privacy is our top priority. Customize your settings below:"
        privacy_message_label = tk.Label(privacy_frame, text=privacy_message, bg=self.light_bg, font=("Helvetica", 16), fg=self.accent_color)
        privacy_message_label.pack()

        # Privacy Settings
        privacy_settings = [
            ("Activity Log", "View your activity log", self.show_activity_log),
            ("Location Services", "Manage apps accessing your location", self.manage_location_services),
            ("App Permissions", "Review and adjust app permissions", self.review_app_permissions),
            ("Browser Privacy", "Enhance your browser privacy", self.enhance_browser_privacy),
            ("Clear History", "Clear your browsing and search history", self.clear_history)
        ]

        for option, desc, command in privacy_settings:
            self.create_privacy_option(privacy_frame, option, desc, command)

    def create_privacy_option(self, parent, text, description, command):
        option_frame = tk.Frame(parent, bg="white", padx=10, pady=10)
        option_frame.pack(side="left", expand=True, fill="both", padx=10)

        btn = tk.Button(option_frame, text=text, compound="top", bg=self.accent_color, fg="white", command=command)
        btn.pack(pady=5)

        desc_label = tk.Label(option_frame, text=description, wraplength=150, justify="center", bg="white", fg="black")
        desc_label.pack()

    def show_activity_log(self):
    # Mock data for the activity log
        activity_log = [
        "2024-02-20 10:00:00 - Full scan completed. No threats found.",
        "2024-02-20 14:30:00 - Real-time protection blocked a threat.",
        "2024-02-20 09:15:00 - Update"
    ]

