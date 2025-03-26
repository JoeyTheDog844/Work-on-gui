import tkinter as tk
from PIL import Image, ImageTk  # Import Pillow for resizing images
import disable_services_gui
from tkinter import messagebox
import automate_rdp_services
import password_policy
import cache_manager
import automate_default_share
import logs_analysis
import export_logs_to_pdf
import threading
import pdf_generator

def on_enter(e, button):
    button.config(bg='#d9d9d9', relief='raised')  # Lighten the button and add raised effect

def on_leave(e, button):
    button.config(bg='#c3c3c3', relief='flat')  # Restore original color and flat style

# Load and Resize Image
image_path = r"C:\Users\amaan\Desktop\hahahhaha-main\test-main\Coding\doggy.jpg"  # Ensure this is the correct path

root = tk.Tk()
root.geometry('780x650')
root.title('CyberSecurity Audit Application')

def show_automate_services():
    """ ✅ Display service statuses in the GUI """
    for widget in automateservices_frame.winfo_children():
        widget.destroy()  # ✅ Clear old labels

    service_statuses = disable_services_gui.check_all_services()  # ✅ Fetch service statuses

    # ✅ Display service names & statuses
    for i, (service, status) in enumerate(service_statuses.items()):
        tk.Label(automateservices_frame, text=service, font=("Arial", 10), anchor="w").grid(row=i, column=0, sticky="w", padx=5, pady=2)
        tk.Label(automateservices_frame, text=status, font=("Arial", 10), fg="green" if status == "Running" else "red").grid(row=i, column=1, padx=5, pady=2)

    # ✅ Buttons for stopping, starting, and disabling services
    stop_button = tk.Button(automateservices_frame, text="STOP ALL SERVICES", font=("Bold", 12), bg="red", fg="white", command=stop_automate_services)
    stop_button.grid(row=len(service_statuses) + 1, column=0, padx=5, pady=10)

    start_button = tk.Button(automateservices_frame, text="START ALL SERVICES", font=("Bold", 12), bg="green", fg="white", command=start_automate_services)
    start_button.grid(row=len(service_statuses) + 1, column=1, padx=5, pady=10)

    disable_button = tk.Button(automateservices_frame, text="DISABLE ALL SERVICES", font=("Bold", 12), bg="gray", fg="white", command=disable_automate_services)
    disable_button.grid(row=len(service_statuses) + 2, column=0, columnspan=2, padx=5, pady=10)

def stop_automate_services():
    """ ✅ Stop all running services """
    stopped_services, failed_services = disable_services_gui.stop_all_services()

    if stopped_services:
        messagebox.showinfo("Services Stopped", f"Successfully stopped:\n" + "\n".join(stopped_services))
    if failed_services:
        messagebox.showwarning("Failed to Stop", f"Could not stop:\n" + "\n".join(failed_services))

    show_automate_services()

def start_automate_services():
    """ ✅ Start all stopped services """
    started_services, failed_services = disable_services_gui.start_all_services()

    if started_services:
        messagebox.showinfo("Services Started", f"Successfully started:\n" + "\n".join(started_services))
    if failed_services:
        messagebox.showwarning("Failed to Start", f"Could not start:\n" + "\n".join(failed_services))

    show_automate_services()

def disable_automate_services():
    """ ✅ Disable all critical services """
    disabled_services, failed_services = disable_services_gui.disable_all_services()

    if disabled_services:
        messagebox.showinfo("Services Disabled", f"Successfully disabled:\n" + "\n".join(disabled_services))
    if failed_services:
        messagebox.showwarning("Failed to Disable", f"Could not disable:\n" + "\n".join(failed_services))

    show_automate_services()

def automateservices_page():
    """ ✅ Show the automate services page """
    delete_pages()
    
    global automateservices_frame
    automateservices_frame = tk.Frame(main_frame)
    automateservices_frame.pack(pady=10, fill="both", expand=True)

    show_automate_services()

def show_rdp_services():
    """ ✅ Display RDP & Remote Services statuses in the GUI """
    for widget in rdp_services_frame.winfo_children():
        widget.destroy()  # ✅ Clear old labels

    service_statuses = automate_rdp_services.check_services_status()  # ✅ Fetch service statuses

    # ✅ Display service names & statuses
    for i, (service, status) in enumerate(service_statuses.items()):
        tk.Label(rdp_services_frame, text=service, font=("Arial", 10), anchor="w").grid(row=i, column=0, sticky="w", padx=5, pady=2)
        tk.Label(rdp_services_frame, text=status, font=("Arial", 10), fg="green" if status == "Running" else "red").grid(row=i, column=1, padx=5, pady=2)

    # ✅ Buttons for stopping, starting, and disabling services
    stop_button = tk.Button(rdp_services_frame, text="STOP SERVICES", font=("Bold", 12), bg="red", fg="white", command=stop_rdp_services)
    stop_button.grid(row=len(service_statuses) + 1, column=0, padx=5, pady=10)

    start_button = tk.Button(rdp_services_frame, text="ENABLE SERVICES", font=("Bold", 12), bg="green", fg="white", command=enable_rdp_services)
    start_button.grid(row=len(service_statuses) + 1, column=1, padx=5, pady=10)

    disable_button = tk.Button(rdp_services_frame, text="DISABLE SERVICES", font=("Bold", 12), bg="gray", fg="white", command=disable_rdp_services)
    disable_button.grid(row=len(service_statuses) + 2, column=0, columnspan=2, padx=5, pady=10)

def stop_rdp_services():
    """ ✅ Stop all RDP & Remote Services (non-blocking) """
    def worker():
        try:
            stopped_services, failed_services = automate_rdp_services.stop_services()

            def update_ui():
                if stopped_services:
                    messagebox.showinfo("Services Stopped", "Successfully stopped:\n" + "\n".join(stopped_services))
                if failed_services:
                    messagebox.showwarning("Failed to Stop", "Could not stop:\n" + "\n".join(failed_services))

                show_rdp_services()

            root.after(0, update_ui)

        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", f"Something went wrong:\n{e}"))

    threading.Thread(target=worker).start()

def enable_rdp_services():
    """ ✅ Enable all RDP & Remote Services """
    enabled_services, failed_services = automate_rdp_services.enable_services()

    if enabled_services:
        messagebox.showinfo("Services Enabled", f"Successfully enabled:\n" + "\n".join(enabled_services))
    if failed_services:
        messagebox.showwarning("Failed to Enable", f"Could not enable:\n" + "\n".join(failed_services))

    show_rdp_services()  # ✅ Refresh the GUI

def disable_rdp_services():
    """ ✅ Disable all RDP & Remote Services """
    disabled_services, failed_services = automate_rdp_services.disable_services()

    if disabled_services:
        messagebox.showinfo("Services Disabled", f"Successfully disabled:\n" + "\n".join(disabled_services))
    if failed_services:
        messagebox.showwarning("Failed to Disable", f"Could not disable:\n" + "\n".join(failed_services))

    show_rdp_services()  # ✅ Refresh the GUI

def rdp_services_page():
    """ ✅ Show the RDP & Remote Services page """
    delete_pages()

    global rdp_services_frame
    rdp_services_frame = tk.Frame(main_frame)
    rdp_services_frame.pack(pady=10, fill="both", expand=True)

    show_rdp_services()

def show_password_policy():
    """ ✅ Display the current password policy in the GUI """
    delete_pages()

    global password_policy_frame
    password_policy_frame = tk.Frame(main_frame)
    password_policy_frame.pack(pady=10, fill="both", expand=True)

    # ✅ Fetch current password policy
    policy_text = password_policy.get_current_policy()

    # ✅ Display Policy in a Label
    policy_label = tk.Label(password_policy_frame, text="Current Password Policy:\n\n" + policy_text,
                            font=("Arial", 10), anchor="w", justify="left")
    policy_label.pack(padx=10, pady=10)

    # ✅ "Apply Password Policy" Button (Inside the Page)
    apply_button = tk.Button(password_policy_frame, text="APPLY PASSWORD POLICY", font=("Bold", 12),
                             bg="blue", fg="white", command=apply_password_policy)
    apply_button.pack(pady=10)

def apply_password_policy():
    """ ✅ Ask for confirmation before applying new password policy """
    confirm = messagebox.askyesno("Confirm Policy Change", "Are you sure you want to apply the new password policy?")
    
    if confirm:  # Only proceed if the user clicks "Yes"
        result = password_policy.set_password_policy()
        messagebox.showinfo("Password Policy Updated", result)

        # ✅ Refresh to show the updated policy
        show_password_policy()

def show_cache_manager():
    delete_pages()

    global cache_manager_frame
    cache_manager_frame = tk.Frame(main_frame)
    cache_manager_frame.pack(pady=10, fill="both", expand=True)

    tk.Label(cache_manager_frame, text="Cache Management", font=("Bold", 20)).pack(pady=10)

    # 🔧 Status/output label
    status_label = tk.Label(cache_manager_frame, text="", font=("Arial", 10), fg="green", wraplength=600, justify="left")
    status_label.pack(pady=10)

    # ✅ Buttons with lambda functions that update the label text
    tk.Button(cache_manager_frame, text="CLEAR ALL CACHE", font=("Bold", 12), bg="purple", fg="white",
              command=lambda: status_label.config(text=cache_manager.clear_all_caches())).pack(pady=5)

    tk.Button(cache_manager_frame, text="CLEAR RECYCLE BIN", font=("Bold", 12), bg="blue", fg="white",
              command=lambda: status_label.config(text=cache_manager.clear_recycle_bin())).pack(pady=5)

    tk.Button(cache_manager_frame, text="CLEAR TEMP FILES", font=("Bold", 12), bg="blue", fg="white",
              command=lambda: status_label.config(text=cache_manager.clear_temp_files())).pack(pady=5)

    tk.Button(cache_manager_frame, text="CLEAR DNS CACHE", font=("Bold", 12), bg="blue", fg="white",
              command=lambda: status_label.config(text=cache_manager.clear_dns_cache())).pack(pady=5)

    tk.Button(cache_manager_frame, text="CLEAR WINDOWS UPDATE CACHE", font=("Bold", 12), bg="blue", fg="white",
              command=lambda: status_label.config(text=cache_manager.clear_windows_update_cache())).pack(pady=5)

def default_share_page():
    """ ✅ Show the Default Admin Share Toggle page """
    delete_pages()

    global default_share_frame
    default_share_frame = tk.Frame(main_frame)
    default_share_frame.pack(pady=10, fill="both", expand=True)

    # Status label
    status_label = tk.Label(default_share_frame, font=("Arial", 12))
    status_label.pack(pady=10)

    # Toggle button (set text dynamically)
    toggle_button = tk.Button(default_share_frame, font=("Bold", 12), width=25)
    toggle_button.pack(pady=10)

    # Restart note
    note_label = tk.Label(default_share_frame, text="* Restart required to apply changes", font=("Arial", 9), fg="gray")
    note_label.pack(pady=5)

    def update_ui():
        is_disabled = automate_default_share.get_admin_share_status()
        if is_disabled:
            status_label.config(text="❌ Default Shares are Disabled", fg="red")
            toggle_button.config(text="Enable Default Shares")
        else:
            status_label.config(text="✅ Default Shares are Enabled", fg="green")
            toggle_button.config(text="Disable Default Shares")

    def toggle_share():
        current_status = automate_default_share.get_admin_share_status()
        success = automate_default_share.set_admin_share_status(disable=not current_status)
        if success:
            update_ui()
            messagebox.showinfo("Success", "Change applied. Please restart your PC to take full effect.")

    toggle_button.config(command=toggle_share)
    update_ui()

def show_logs_page():
    delete_pages()

    global logs_frame
    logs_frame = tk.Frame(main_frame)
    logs_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Title
    tk.Label(logs_frame, text="System Logs Viewer", font=("Bold", 20)).pack(pady=10)

    # Text widget with scrollbar
    text_scroll = tk.Scrollbar(logs_frame)
    text_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    log_text = tk.Text(logs_frame, wrap="word", font=("Consolas", 9), yscrollcommand=text_scroll.set)
    log_text.pack(fill="both", expand=True)

    text_scroll.config(command=log_text.yview)

    # Fetch logs
    log_text.insert(tk.END, "🔌 USB Logs:\n" + logs_analysis.get_usb_logs() + "\n\n")
    log_text.insert(tk.END, "🔐 Security Logs:\n" + logs_analysis.get_security_logs() + "\n\n")
    log_text.insert(tk.END, "🖥️ System Logs:\n" + logs_analysis.get_system_logs() + "\n\n")
    log_text.insert(tk.END, "📦 Application Logs:\n" + logs_analysis.get_application_logs() + "\n\n")
    log_text.insert(tk.END, "🌐 DNS Logs:\n" + logs_analysis.get_dns_logs() + "\n\n")

    log_text.config(state="disabled")  # Make read-only

    # Export Logs Button
    tk.Button(logs_frame, text="EXPORT LOGS TO PDF", font=("Bold", 12), bg="green", fg="white",
              command=export_logs).pack(pady=10)

def export_logs():
    try:
        path = export_logs_to_pdf.export_logs_to_pdf()
        messagebox.showinfo("Success", f"Logs exported to:\n{path}")
    except Exception as e:
        messagebox.showerror("Error", f"Export failed:\n{e}")

def home_page():
    delete_pages()

    global home_frame
    home_frame = tk.Frame(main_frame)
    home_frame.pack(pady=20, fill="both", expand=True)

    # Title
    tk.Label(home_frame, text='CyberSecurity\nAudit Application', font=('Bold', 30)).pack(pady=20)

    # Subtitle
    tk.Label(home_frame, text='Generate Full Cyber Security Audit Report', font=('Arial', 14)).pack(pady=10)

    # Name Entry
    tk.Label(home_frame, text="Enter User Name:", font=("Arial", 12)).pack()
    name_entry = tk.Entry(home_frame, font=("Arial", 12), width=30)
    name_entry.pack(pady=5)

    # Lab Entry
    tk.Label(home_frame, text="Enter Lab Name:", font=("Arial", 12)).pack()
    lab_entry = tk.Entry(home_frame, font=("Arial", 12), width=30)
    lab_entry.pack(pady=5)

    # Status label
    status_label = tk.Label(home_frame, text="", font=("Arial", 11), fg="green")
    status_label.pack(pady=5)

    # Submit Button
    def generate_report():
        user_name = name_entry.get().strip()
        lab_name = lab_entry.get().strip()

        if not user_name or not lab_name:
            messagebox.showwarning("Input Required", "Please enter both Name and Lab.")
            return

        # ✅ Background thread to avoid freezing
        def run():
            try:
                status_label.config(text="Generating PDF, please wait...", fg="blue")
                pdf_generator.generate_pdf_report(user_name, lab_name)
                root.after(0, lambda: status_label.config(text="✅ Report generated successfully!", fg="green"))
                root.after(0, lambda: messagebox.showinfo("Done", "PDF Report has been generated."))
            except Exception as e:
                root.after(0, lambda: status_label.config(text="❌ Failed to generate report.", fg="red"))
                root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=run).start()

    tk.Button(home_frame, text="GENERATE REPORT", font=('Bold', 14), bg="green", fg="white", command=generate_report).pack(pady=15)

def hide_indicators():
    home_indicate.config(bg='#c3c3c3')
    automateservices_indicate.config(bg='#c3c3c3')
    rdp_services_indicate.config(bg='#c3c3c3')
    password_policy_indicate.config(bg='#c3c3c3')
    cache_manager_indicate.config(bg='#c3c3c3')
    default_share_indicate.config(bg='#c3c3c3')
    logs_analysis_indicate.config(bg='#c3c3c3')

def delete_pages():
    for frame in main_frame.winfo_children():
        frame.destroy()

def indicate(lb, page):
    hide_indicators()
    lb.config(bg='#158aff')
    delete_pages()
    page()

# Sidebar container frame (Now it does NOT restrict options_frame)
sidebar_frame = tk.Frame(root, bg='#c3c3c3')

# Options Frame (Manually set its width again)
options_frame = tk.Frame(sidebar_frame, bg='#c3c3c3', width=140, height=600)
options_frame.configure(width=140, height=600)  # Explicitly set size

# Load and Resize Logo (Separate from options_frame)
try:
    original_image = Image.open(image_path)
    resized_image = original_image.resize((95, 95), Image.LANCZOS)  # Resize to fit
    logo_img = ImageTk.PhotoImage(resized_image)  # Convert to Tkinter-compatible format

    logo_label = tk.Label(sidebar_frame, image=logo_img, bg='#c3c3c3')
    logo_label.pack(pady=10)  # Align properly
except Exception as e:
    print(f"Error loading logo: {e}")

# Create indicators first before buttons to avoid NameError
home_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
home_indicate.grid(row=0, column=0, sticky="w", padx=5)

automateservices_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
automateservices_indicate.grid(row=1, column=0, sticky="w", padx=5)

rdp_services_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
rdp_services_indicate.grid(row=2, column=0, sticky="w", padx=5)

password_policy_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
password_policy_indicate.grid(row=3, column=0, sticky="w", padx=5)

cache_manager_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
cache_manager_indicate.grid(row=4, column=0, sticky="w", padx=5)

default_share_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
default_share_indicate.grid(row=5, column=0, sticky="w", padx=5)

logs_analysis_indicate = tk.Label(options_frame, text='', bg='#c3c3c3')
logs_analysis_indicate.grid(row=6, column=0, sticky="w", padx=5)

# Configure the options_frame for perfect alignment
options_frame.grid_columnconfigure(1, weight=1)  # Ensure buttons expand evenly

# Home Button
home_btn = tk.Button(
    options_frame, text='HOME', font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(home_indicate, home_page)
)
home_btn.grid(row=0, column=1, sticky="ew", padx=10, pady=10)
home_btn.bind('<Enter>', lambda e: on_enter(e, home_btn))
home_btn.bind('<Leave>', lambda e: on_leave(e, home_btn))

# DISABLE Services Button
automateservices_btn = tk.Button(
    options_frame, text='DISABLE\nSERVICES', font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(automateservices_indicate, automateservices_page)
)
automateservices_btn.grid(row=1, column=1, sticky="ew", padx=10, pady=10)
automateservices_btn.bind('<Enter>', lambda e: on_enter(e, automateservices_btn))
automateservices_btn.bind('<Leave>', lambda e: on_leave(e, automateservices_btn))

# Automate RDP Services Button
rdp_services_btn = tk.Button(
    options_frame, text='AUTOMATE\nRDP SERVICES', font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(rdp_services_indicate, rdp_services_page)
)
rdp_services_btn.grid(row=2, column=1, sticky="ew", padx=10, pady=10)
rdp_services_btn.bind('<Enter>', lambda e: on_enter(e, rdp_services_btn))
rdp_services_btn.bind('<Leave>', lambda e: on_leave(e, rdp_services_btn))

# Password Policy Button
password_policy_btn = tk.Button(
    options_frame, text="SET PASSWORD\nPOLICY", font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(password_policy_indicate, show_password_policy)  # ✅ Opens policy page instead
)
password_policy_btn.grid(row=3, column=1, sticky="ew", padx=10, pady=10)
password_policy_btn.bind('<Enter>', lambda e: on_enter(e, password_policy_btn))
password_policy_btn.bind('<Leave>', lambda e: on_leave(e, password_policy_btn))

# Manage Cache
cache_manager_btn = tk.Button(
    options_frame, text="MANAGE\nCACHE", font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(cache_manager_indicate, show_cache_manager)  # ✅ Opens policy page instead
)
cache_manager_btn.grid(row=4, column=1, sticky="ew", padx=10, pady=10)
cache_manager_btn.bind('<Enter>', lambda e: on_enter(e, cache_manager_btn))
cache_manager_btn.bind('<Leave>', lambda e: on_leave(e, cache_manager_btn))

# Default Share
default_share_btn = tk.Button(
    options_frame, text="DEFAULT SHARE\nSETTINGS", font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(default_share_indicate, default_share_page)
)
default_share_btn.grid(row=5, column=1, sticky="ew", padx=10, pady=10)
default_share_btn.bind('<Enter>', lambda e: on_enter(e, default_share_btn))
default_share_btn.bind('<Leave>', lambda e: on_leave(e, default_share_btn))

# Logs
logs_analysis_btn = tk.Button(
    options_frame, text="VIEW\nLOGS", font=('Bold', 15),
    fg='#158aff', bd=0, bg='#c3c3c3', relief='flat',
    command=lambda: indicate(logs_analysis_indicate, show_logs_page)
)
logs_analysis_btn.grid(row=6, column=1, sticky="ew", padx=10, pady=10)
logs_analysis_btn.bind('<Enter>', lambda e: on_enter(e, logs_analysis_btn))
logs_analysis_btn.bind('<Leave>', lambda e: on_leave(e, logs_analysis_btn))

# Pack everything properly
options_frame.pack(fill="both", expand=False)  # Now it can be resized manually
sidebar_frame.pack(side=tk.LEFT, fill="y")  # Sidebar keeps full height

# Main content area
main_frame = tk.Frame(root, highlightbackground='black', highlightthickness=2)
main_frame.pack(side=tk.LEFT, fill="both", expand=True)

root.mainloop()
