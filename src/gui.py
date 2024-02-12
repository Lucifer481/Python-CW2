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
root.geometry("1024x768")  # Adjust to your screen

# Define the main color scheme
dark_bg = "#333333"
light_bg = "#f0f0f0"
accent_color = "#30c030"

# Load images (replace 'placeholder.png' with your actual images)
dashboard_icon = PhotoImage(file="img/scan.png")  # Replace with actual path
protection_icon = PhotoImage(file="img/scan.png")
privacy_icon = PhotoImage(file="img/scan.png")
notification_icon = PhotoImage(file="img/scan.png")