import os
import tkinter as tk
from tkinter import Listbox, filedialog, messagebox, Menu, Label, Button, Entry, Toplevel, Text, Scrollbar
from tkinter import ttk
from PIL import Image, ImageTk
from tkinter import ttk, PhotoImage
import requests
import time
import json
import random
import threading


# Load API key from environment variable
api_key = os.getenv('VIRUSTOTAL_API_KEY')

 # Initialize the main window
root = tk.Tk()
root.title("Antivirus Application")
root.geometry("1024x768")  

# Define the main color scheme
dark_bg = "#333333"
light_bg = "#f0f0f0"
accent_color = "#30c030"
light_text = "#FFFFFF"

# SideBar
sidebar = tk.Frame(root, bg=dark_bg, width=200, height=768)
sidebar.pack(side='left', fill='y')

# Add buttons to the sidebar
buttons_text = ["Dashboard", "Protection", "Privacy", "Notifications", "My Account", "Setting", "Help"]
for text in buttons_text:
    button = tk.Button(sidebar, text=text, fg=light_text, bg=dark_bg, bd=0, padx=20, pady=10)
    button.pack(fill="x")

# Content Area
content = tk.Frame(root, bg=light_bg)
content.pack(expand=True, fill='both')

# Load background image (ensure the path is correct)
bg_image = Image.open('img/bg.jpg')  # Use 'path_to_your_background.jpg'
bg_photo = ImageTk.PhotoImage(bg_image)
bg_label = tk.Label(content, image=bg_photo)
bg_label.place(relwidth=1, relheight=1)

# Protection tab
protection_tab = ttk.Frame(content, padding=10)
protection_tab.pack(fill='both', expand=True)
protection_tab.grid_columnconfigure(0,weight=1)
protection_tab.grid_rowconfigure(0,weight=1)

# Load images for buttons (ensure the paths are correct)
quick_scan_img = ImageTk.PhotoImage(Image.open('img/bg.jpg'))  # JPG image
system_scan_img = ImageTk.PhotoImage(Image.open('img/scan.png'))  # PNG image
custom_scan_img = ImageTk.PhotoImage(Image.open('img/search.png'))

# Create a frame for the protection options
protection_frame = tk.Frame(content, bg="white", pady=20)
protection_frame.pack(fill="x")

 # Scan options frame placed in the center
scan_options_frame = tk.Frame(protection_tab, bg=light_bg)
scan_options_frame.grid(row=0, column=0, sticky="nsew")

        # Scan options with images, descriptions, and a touch of Omega charm
scan_options = [
            ("Quick Scan", quick_scan_img, "Scan the shadows where malware lurks."),
            ("System Scan", system_scan_img, "Unleash a full-scale digital purge."),
            ("Custom Scan", custom_scan_img, "Handpick targets or drop files for an epic scan.")
        ]
# Configure weight for each column within scan_options_frame
for i in range(len(scan_options)):
            scan_options_frame.grid_columnconfigure(i, weight=1)

for option, img, desc in scan_options:
            option_frame = tk.Frame(scan_options_frame, bg="white", padx=10, pady=10, highlightbackground=accent_color, highlightthickness=2)
            option_frame.grid(row=0, column=scan_options.index((option, img, desc)), padx=10, pady=10, sticky="nsew")

            tk.Label(option_frame, image=img, bg="white").pack()
            tk.Label(option_frame, text=option, bg="white", fg="black", font=('Arial', 14, 'bold')).pack()
            tk.Label(option_frame, text=desc, bg="white", fg="gray").pack()
            tk.Button(option_frame, text="Initiate Scan", bg=accent_color, fg="white", font=('Arial', 10, 'bold')).pack(pady=5)

root.mainloop()