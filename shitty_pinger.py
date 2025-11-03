import tkinter as tk
import threading
import time
import random

ASCII_ART = r"""
   /$$     /$$                                 /$$          
  | $$    | $$                                | $$          
 /$$$$$$  | $$$$$$$   /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ 
|_  $$_/  | $$__  $$ /$$__  $$| $$__  $$ /$$__  $$ /$$__  $$
  | $$    | $$  \ $$| $$$$$$$$| $$  \ $$| $$  | $$| $$  \ $$
  | $$ /$$| $$  | $$| $$_____/| $$  \ $$| $$  | $$| $$  | $$
  |  $$$$/| $$$$$$$/|  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$/
   \___/  |__/____/  \_______/|__/  |__/ \_______/ \______/ 
                                                            
"""

def run_attack(text_widget):
    def init_ui():
        text_widget.delete('1.0', tk.END)
        text_widget.insert(tk.END, ASCII_ART + "\n")
        text_widget.insert('end', f"Target IP: {ip}\n\n", ("ip",))
        text_widget.tag_config("ascii", foreground="red", font=("Courier", 14, "bold"))
        text_widget.tag_config("ip", foreground="yellow", font=("Courier", 12, "bold"))
        text_widget.see(tk.END)
    text_widget.after(0, init_ui)

    total_packets = 10000000  # 10 million for a big attack
    start_time = time.time()

     messages = [
        "IP flooding detected",
        "Open ports scanning in progress",
        "Suspicious activity from IP",
        "Packet loss to IP",
        "Bandwidth congestion on IP",
        "Firewall bypass attempt from IP",
        "Multiple connection attempts from IP",
        "Port 80/443 under attack",
        "DDoS traffic targeting IP",
        "Potential breach on IP"
    ]

    def update_progress(p):
        def do_update():
            text_widget.delete('3.0', tk.END)
            text_widget.insert('1.0', ASCII_ART + "\n")
            text_widget.insert('end', f"Target IP: {ip}\n\n", ("ip",))
            text_widget.insert('end', f"Packets sent: {p}\n")
        text_widget.after(0, do_update)

    def send_packets():
        current_packet = 0
        while current_packet < total_packets:
            current_packet += 1

            if current_packet % 1000 == 0 or current_packet == total_packets:
                update_progress(current_packet)

            # time.sleep(0.000001)  # optional, to slow down slightly
        total_time = time.time() - start_time

        def finish():
            text_widget.delete('3.0', tk.END)
            text_widget.insert('1.0', ASCII_ART + "\n")
            text_widget.insert('end', f"Target IP: {ip}\n\n", ("ip",))
            text_widget.insert('end', f"Finished in {total_time:.2f} seconds.\n")
            for msg in [
                "IP COMPROMISED",
                "BACKDOOR OPENED",
                "PACKET TRAFFIC SUCCESS",
                "THENDO HAS GOT YOU",
                "NO ESCAPE"
            ]:
                text_widget.insert('end', f"{msg}\n", ("scary",))
            text_widget.see(tk.END)

    
        text_widget.after(0, finish)

    threading.Thread(target=send_packets, daemon=True).start()

root = tk.Tk()
root.title("DDoS Attack Simulation")
root.attributes('-fullscreen', True)
root.configure(bg='black')

text = tk.Text(root, bg='black', fg='red', font=('Courier', 12))
text.pack(expand=True, fill=tk.BOTH)

def center_window(win, width=300, height=150):
    win.update_idletasks()
    w = win.winfo_screenwidth()
    h = win.winfo_screenheight()
    x = (w - width) // 2
    y = (h - height) // 2
    win.geometry(f"{width}x{height}+{x}+{y}")

def start_simulation():
    dlg = tk.Toplevel(root)
    dlg.title("Enter Access Code")
    dlg.grab_set()
    center_window(dlg, 300, 150)
    lbl = tk.Label(dlg, text="Enter the access code:")
    lbl.pack(pady=10)
    code_entry = tk.Entry(dlg, show='*')
    code_entry.pack(pady=5)

    def submit():
        global ip
        code = code_entry.get()
        dlg.destroy()
        if code != "161120":
            text.insert('end', "Incorrect code. Access denied.\n")
            text.see(tk.END)
            return
        ip_dlg = tk.Toplevel(root)
        ip_dlg.title("Target IP")
        ip_dlg.grab_set()
        center_window(ip_dlg, 300, 100)
        lbl_ip = tk.Label(ip_dlg, text="Enter target IP :")
        lbl_ip.pack(pady=10)
        ip_entry = tk.Entry(ip_dlg)
        ip_entry.pack(pady=5)

        def get_ip():
            global ip
            ip_input = ip_entry.get()
            if not ip_input:
                ip = f"192.168.1.{random.randint(2, 254)}"
            else:
                ip = ip_input
            ip_dlg.destroy()
            threading.Thread(target=run_attack, args=(text,), daemon=True).start()

        center_window(ip_dlg, 300, 100)
        start_btn = tk.Button(ip_dlg, text="Start Attack", command=get_ip)
        start_btn.pack(pady=10)

    center_window(dlg, 300, 150)
    btn = tk.Button(dlg, text="Enter", command=submit)
    btn.pack(pady=10)

root.after(100, start_simulation)
root.mainloop()