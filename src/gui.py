import platform
import tkinter as tk
from tkinter import Checkbutton, IntVar, Listbox, Text, filedialog, messagebox, Toplevel, Label, Entry, Button
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
        activity_log_window = Toplevel(self.master)
        activity_log_window.title("Activity Log")
        activity_log_window.geometry("600x400")
    
        log_text = Text(activity_log_window, wrap="word")
        log_text.pack(padx=20, pady=20, fill="both", expand=True)
    
        for entry in activity_log:
            log_text.insert("end", entry + "\n")
        log_text.config(state="disabled") 

    def manage_location_services(self):
        location_settings_window = Toplevel(self.master)
        location_settings_window.title("Location Services")

        location_status_label = Label(location_settings_window, text="Location Services are currently enabled.", font=("Helvetica", 14))
        location_status_label.pack(padx=20, pady=20)

        toggle_location_button = Button(location_settings_window, text="Location Services", command=lambda: self.toggle_location(location_status_label))
        toggle_location_button.pack(pady=10)

    def toggle_location(self, status_label):
        current_status = status_label.cget("text")
        new_status = "Location Services are currently " + ("disabled." if "enabled" in current_status else "enabled.")
        status_label.config(text=new_status)

    def review_app_permissions(self):
        # Simulated data structure to hold app permissions and their states
        self.app_permissions = {
            "App1": {"Camera": True, "Microphone": False, "Location": True},
            "App2": {"Contacts": True, "Storage": False},
            "App3": {"Notifications": True, "Background Refresh": False}
        }

        permissions_window = Toplevel(self.master)
        permissions_window.title("App Permissions")
        permissions_window.geometry("500x400")

        for app, permissions in self.app_permissions.items():
            app_frame = tk.LabelFrame(permissions_window, text=app, padx=10, pady=10)
            app_frame.pack(padx=10, pady=5, fill="x")

            for permission, enabled in permissions.items():
                self._create_permission_toggle(app_frame, app, permission, enabled)
    

    def _create_permission_toggle(self, parent, app_name, permission, enabled):
        var = IntVar(value=enabled)
        chk = Checkbutton(parent, text=permission, variable=var, onvalue=1, offvalue=0,
                          command=lambda: self._toggle_permission(app_name, permission, var))
        chk.pack(anchor="w")
    
    def _toggle_permission(self, app_name, permission, var):
        # Update the app_permissions data structure based on the checkbox state
        self.app_permissions[app_name][permission] = bool(var.get())
        # Placeholder for actual permission toggle logic
        print(f"Permission {permission} for {app_name} set to {'enabled' if var.get() else 'disabled'}")
        messagebox.showinfo("Permission Toggled", f"{permission} for {app_name} {'enabled' if var.get() else 'disabled'}.")

    def enhance_browser_privacy(self):
        browser_privacy_window = Toplevel(self.master)
        browser_privacy_window.title("Enhance Browser Privacy")

        enhance_browser_label = Label(browser_privacy_window, text="Choose options to enhance your browser privacy:", font=("Helvetica", 14))
        enhance_browser_label.pack(padx=20, pady=20)

        clear_cookies_button = Button(browser_privacy_window, text="Clear Cookies", command=self.clear_cookies)
        clear_cookies_button.pack(pady=10)

        enable_tracking_protection_button = Button(browser_privacy_window, text="Enable Tracking Protection", command=self.enable_tracking_protection)
        enable_tracking_protection_button.pack(pady=10)

    def clear_cookies(self):
        messagebox.showinfo("Clear Cookies", "Cookies cleared successfully.")

    def enable_tracking_protection(self):
        messagebox.showinfo("Enable Tracking Protection", "Tracking protection enabled successfully.")

    def clear_history(self):
        messagebox.showinfo("Clear History", "Browsing history cleared successfully.")

    def show_about_page(self):
        for widget in self.content.winfo_children():
            widget.destroy()

        about_frame = tk.Frame(self.content, bg=self.light_bg)
        about_frame.pack(expand=True, fill='both')

    # Cool logo or image for your application
        about_logo_img = ImageTk.PhotoImage(Image.open('logo.png'))
        about_logo_label = tk.Label(about_frame, image=about_logo_img, bg=self.light_bg)
        about_logo_label.image = about_logo_img
        about_logo_label.pack(pady=20)

    # Application Name and Version
        app_name_label = tk.Label(about_frame, text="Cool Antivirus", font=("Helvetica", 24, "bold"), fg=self.accent_color, bg=self.light_bg)
        app_version_label = tk.Label(about_frame, text="Version 1.0", font=("Helvetica", 16), fg="gray", bg=self.light_bg)
        app_name_label.pack()
        app_version_label.pack(pady=10)

    # Description
        about_description = (
            "Cool Antivirus is a state-of-the-art application designed to protect your PC from all kinds of cyber threats. "
            "With advanced scanning options, real-time protection, and enhanced privacy controls, your digital world is in safe hands."
        )
        description_label = tk.Label(about_frame, text=about_description, font=("Helvetica", 14), wraplength=600, justify="center", bg=self.light_bg, fg="black")
        description_label.pack(pady=20)

    # Credits and Acknowledgments
        credits_label = tk.Label(about_frame, text="Credits & Acknowledgments", font=("Helvetica", 18, "bold"), fg=self.accent_color, bg=self.light_bg)
        credits_label.pack(pady=10)

        about_credits = (
            "Special thanks to our amazing development team for bringing this application to life. "
            "We also extend our gratitude to the open-source community and everyone who contributed to the success of Cool Antivirus."
        )
        credits_description_label = tk.Label(about_frame, text=about_credits, font=("Helvetica", 14), wraplength=600, justify="center", bg=self.light_bg, fg="black")
        credits_description_label.pack(pady=20)

    # Close button
        close_button = tk.Button(about_frame, text="Close", bg=self.accent_color, fg="white", command=lambda: self.update_content("Your PC is Great"))
        close_button.pack(pady=20)

    
