import tkinter as tk
from tkinter import messagebox
import threading
import time

# Assuming a simple achievements structure
achievements = {
    "first_scan": {
        "name": "First Scan",
        "description": "Complete your first full system scan.",
        "reward": 100,
        "unlocked": False
    }
}

user_points = 0

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        root.title("Simple Antivirus")

        # Scan Button
        self.scan_btn = tk.Button(root, text="Run Scan", command=self.run_scan)
        self.scan_btn.pack(pady=20)

        # Points Display
        self.points_label = tk.Label(root, text=f"Points: {user_points}")
        self.points_label.pack(pady=10)

    def run_scan(self):
        # Simulate a scan
        threading.Thread(target=self.simulate_scan).start()

    def simulate_scan(self):
        time.sleep(2)  # Simulate time taken to scan
        self.scan_completed()

    def scan_completed(self):
        # Update UI thread-safe
        self.root.after(0, self.update_achievement_status, "first_scan")

    def update_achievement_status(self, achievement_key):
        global user_points
        achievement = achievements[achievement_key]
        if not achievement["unlocked"]:
            achievement["unlocked"] = True
            user_points += achievement["reward"]
            self.update_points_display(user_points)
            messagebox.showinfo("Achievement Unlocked", f"{achievement['name']}!\n{achievement['description']}\nReward: {achievement['reward']} points")

    def update_points_display(self, points):
        self.points_label.config(text=f"Points: {points}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
