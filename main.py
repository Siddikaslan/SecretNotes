import binascii
import tkinter
from tkinter import PhotoImage, END, messagebox
import base64

window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=400, height=700)
window.config(pady=30, padx=30)
FONT = ("ariel" , 14)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = title_entry.get()
    secret = text_secret.get("1.0",END)
    master_key = master_key_entry.get()

    if not title or not secret or not master_key:
        messagebox.showwarning("Alert","Please enter all information.")
        return

    else:
        encrypted_secret = encode(master_key, secret)
        try:
            with open("Secrets.txt","a") as file:
                file.write(f"Title: {title}\n")
                file.write(f"Secret: {encrypted_secret}\n")
        except FileNotFoundError:
            with open("Secrets.txt", "w") as file:
                file.write(f"Title: {title}\n")
                file.write(f"Secret: {encrypted_secret}\n")
        finally:
            title_entry.delete(0,END)
            text_secret.delete("1.0", END)
            master_key_entry.delete(0, END)

def decrypt():
    encrypted_secret = text_secret.get("1.0", END)
    master_key = master_key_entry.get()

    if  not encrypted_secret or not master_key:
        messagebox.showwarning("Alert","Please enter all information.")

    else:
        try:
            decrypted_secret = decode(master_key, encrypted_secret)
            text_secret.delete("1.0", END)
            text_secret.insert("1.0", decrypted_secret)
        except binascii.Error:
            messagebox.showwarning("Alert", f"Please enter decrypt secret!")


img = PhotoImage(file="scrt.png")
img_label = tkinter.Label(image=img)
img_label.pack(pady=20)


enter_title = tkinter.Label(text="Enter your title", font=FONT)
enter_title.pack(pady=5)
title_entry = tkinter.Entry(width=30)
title_entry.pack(pady=3)


enter_secret = tkinter.Label(text="Enter your secret",font=FONT)
enter_secret.pack(pady=3)
text_secret = tkinter.Text(width=40 , height= 15)
text_secret.pack(pady=3)


enter_master_key = tkinter.Label(text="Enter master key", font=FONT)
enter_master_key.pack(pady=3)
master_key_entry = tkinter.Entry(width=30)
master_key_entry.pack(pady=3)


save_button = tkinter.Button(text="Save & Encrypt", font=FONT, command=save_and_encrypt)
save_button.pack(pady=3)

decrypt_button= tkinter.Button(text="Decrypt",font=FONT, command=decrypt)
decrypt_button.pack(pady=3)

window.mainloop()