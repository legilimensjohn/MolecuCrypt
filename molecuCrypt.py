import tkinter as tk  # Import tkinter for GUI
from tkinter import messagebox  # Import messagebox for error dialogs

# --- Molecular/Bitshift Functions ---

def text_to_binary(text):
    # Convert each character in the text to its 8-bit binary representation and join them into a string
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    # Convert a binary string (without spaces) back to text, 8 bits at a time
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def shift_bits(binary, shift, direction="encrypt"):
    # Circularly shift each byte (8 bits) in the binary string
    shifted = ""
    for byte in binary.split():  # Split the binary string into bytes
        shift = shift % 8  # Ensure shift is within 0-7
        if direction == "encrypt":
            # For encryption, shift left
            shifted_byte = byte[shift:] + byte[:shift]
        else:
            # For decryption, shift right
            shifted_byte = byte[-shift:] + byte[:-shift]
        shifted += shifted_byte + " "  # Add shifted byte to result
    return shifted.strip()  # Remove trailing space

def binary_to_molecular(binary):
    # Encode binary to molecular format: 0 -> '-', 1 -> '=', space -> '≡'
    molecular = binary.replace('0', '-').replace('1', '=')
    return molecular.replace(" ", "≡")

def molecular_to_binary(molecular):
    # Decode molecular format back to binary: '-' -> 0, '=' -> 1, '≡' -> space
    return molecular.replace('-', '0').replace('=', '1').replace('≡', ' ')

def encrypt(text, shift=2):
    # Encrypt the input text using molecular encoding and bitwise shifting
    try:
        binary = text_to_binary(text)  # Convert text to binary
        # Split binary into bytes, shift, then encode
        shifted_binary = shift_bits(' '.join(binary[i:i+8] for i in range(0, len(binary), 8)), shift, "encrypt")
        molecular = binary_to_molecular(shifted_binary)  # Encode to molecular
        encrypted_word = binary_to_text(shifted_binary.replace(" ", ""))  # Convert shifted binary to text
        return molecular, shifted_binary, encrypted_word  # Return all representations
    except Exception as e:
        return f"Error during encryption: {e}", "", ""

def decrypt(molecular, shift=2):
    # Decrypt the molecular string using the provided shift value
    try:
        binary = molecular_to_binary(molecular)  # Decode molecular to binary
        shifted_binary = shift_bits(binary, shift, "decrypt")  # Reverse shift
        return binary_to_text(shifted_binary.replace(" ", ""))  # Convert to text
    except Exception as e:
        return f"Error during decryption: {e}"

def manual_decrypt(molecular, shift=2):
    # Show step-by-step decryption for educational purposes
    try:
        binary = molecular_to_binary(molecular)  # Step 1: molecular to binary
        shifted_binary = shift_bits(binary, shift, "decrypt")  # Step 2: reverse shift
        text = binary_to_text(shifted_binary.replace(" ", ""))  # Step 3: binary to text
        return f"Step 1: Molecular to Binary: {binary}\n" \
               f"Step 2: Reverse Bit Shift: {shifted_binary}\n" \
               f"Step 3: Binary to Text: {text}"
    except Exception as e:
        return f"Error during manual decryption: {e}"
    
def handle_clear():
    # Clear all input and output fields
    entry_text.delete(0, tk.END)
    entry_shift.delete(0, tk.END)
    result_label.config(text="Result will be displayed here.")


# --- GUI Functions ---

def handle_encrypt():
    # Handle the Encrypt button click event
    text = entry_text.get()  # Get text from input field
    shift = entry_shift.get()  # Get shift value from input field
    if not text:
        messagebox.showerror("Error", "Please enter text to encrypt.")  # Show error if text is empty
        return
    if not shift.isdigit() or int(shift) <= 0 or int(shift) > 255:
        messagebox.showerror("Error", "Shift must be a positive integer between 1 and 255.")  # Validate shift
        return
    molecular, shifted_binary, encrypted_word = encrypt(text, int(shift))  # Encrypt the text
    # Convert each 8 bits (byte) of shifted_binary to hex, separated by spaces
    hex_bytes = []
    for byte in shifted_binary.split():
        hex_byte = hex(int(byte, 2))[2:].upper()  # Convert byte to hex
        if len(hex_byte) == 1:
            hex_byte = "0" + hex_byte  # Pad single digit hex
        hex_bytes.append(hex_byte)
    hex_output = " ".join(hex_bytes)  # Join hex bytes
    # Display all results in the result label
    result_label.config(text=f"Encrypted Molecular Bonds:\n{molecular}\n\n"
                             f"Encrypted Binary:\n{shifted_binary}\n\n"
                             f"Encrypted Binary (Hex):\n{hex_output}\n\n"
                             f"Final Encrypted Word:\n{encrypted_word}")

def handle_decrypt():
    # Handle the Decrypt button click event
    molecular = entry_text.get()  # Get molecular string from input field
    shift = entry_shift.get()  # Get shift value from input field
    if not molecular:
        messagebox.showerror("Error", "Please enter molecular bonds to decrypt.")  # Show error if empty
        return
    if not shift.isdigit() or int(shift) <= 0 or int(shift) > 255:
        messagebox.showerror("Error", "Shift must be a positive integer between 1 and 255.")  # Validate shift
        return
    decrypted = decrypt(molecular, int(shift))  # Decrypt the molecular string
    result_label.config(text=f"Decrypted Text:\n{decrypted}")  # Display result

def handle_manual_decrypt():
    # Handle the Manual Decrypt button click event (shows step-by-step)
    molecular = entry_text.get()  # Get molecular string from input field
    shift = entry_shift.get()  # Get shift value from input field
    if not molecular:
        messagebox.showerror("Error", "Please enter molecular bonds to decrypt.")  # Show error if empty
        return
    if not shift.isdigit() or int(shift) <= 0 or int(shift) > 255:
        messagebox.showerror("Error", "Shift must be a positive integer between 1 and 255.")  # Validate shift
        return
    steps = manual_decrypt(molecular, int(shift))  # Get step-by-step decryption
    result_label.config(text=f"Manual Decryption Steps:\n\n{steps}")  # Display steps

# --- GUI Setup ---

root = tk.Tk()  # Create main window
root.title("MolecuCrypt")  # Set window title
root.geometry("750x600")  # Set window size

input_frame = tk.Frame(root)  # Create input frame
input_frame.pack(pady=10)  # Add padding

# Label and entry for text or molecular bonds
tk.Label(input_frame, text="Enter Text or Molecular Bonds:", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w", padx=5, pady=5)
entry_text = tk.Entry(input_frame, width=50, font=("Helvetica", 12))
entry_text.grid(row=0, column=1, padx=5, pady=5)

# Label and entry for shift value
tk.Label(input_frame, text="Enter Shift (1 to 255):", font=("Helvetica", 12)).grid(row=1, column=0, sticky="w", padx=5, pady=5)
entry_shift = tk.Entry(input_frame, width=20, font=("Helvetica", 12))
entry_shift.grid(row=1, column=1, padx=5, pady=5, sticky="w")

button_frame = tk.Frame(root)  # Create button frame
button_frame.pack(pady=15)

# Encrypt button
tk.Button(button_frame, text="Encrypt", command=handle_encrypt,
          width=15, font=("Helvetica", 11, "bold"), bg="#4CAF50", fg="white").grid(row=0, column=0, padx=10)

# Decrypt button
tk.Button(button_frame, text="Decrypt", command=handle_decrypt,
          width=15, font=("Helvetica", 11, "bold"), bg="#2196F3", fg="white").grid(row=0, column=1, padx=10)

# Manual Decrypt button
tk.Button(button_frame, text="Manual Decrypt", command=handle_manual_decrypt,
          width=20, font=("Helvetica", 11, "bold"), bg="#FF9800", fg="white").grid(row=0, column=2, padx=10)

# Manual Decrypt button
tk.Button(button_frame, text="Manual Decrypt", command=handle_manual_decrypt,
          width=20, font=("Helvetica", 11, "bold"), bg="#FF9800", fg="white").grid(row=0, column=2, padx=10)

# Clear button
tk.Button(button_frame, text="Clear", command=handle_clear,
          width=10, font=("Helvetica", 11), bg="#E0E0E0", fg="black").grid(row=0, column=3, padx=10)

result_frame = tk.Frame(root)  # Create result frame
result_frame.pack(pady=15, fill="both", expand=True)

# Label to display results
result_label = tk.Label(result_frame, text="Result will be displayed here.", wraplength=550, justify="left", font=("Courier New", 11))
result_label.pack(padx=10, pady=10)

root.mainloop()  # Start the GUI event loop