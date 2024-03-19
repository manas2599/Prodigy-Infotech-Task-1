def caesar_cipher(text, shift, mode):
    result = ''
    for char in text:
        if char.isalpha():
            if char.islower():
                offset = ord('a')
            else:
                offset = ord('A')
            shifted = (ord(char) - offset + shift) % 26 + offset
            result += chr(shifted)
        else:
            result += char
    return result


def encrypt(text, shift):
    return caesar_cipher(text, shift, 'encrypt')


def decrypt(text, shift):
    return caesar_cipher(text, -shift, 'decrypt')


def main():
    while True:
        choice = input("Enter 'e' to encrypt or 'd' to decrypt (q to quit): ").lower()
        if choice == 'q':
            break
        elif choice == 'e':
            message = input("Enter the message to encrypt: ")
            shift = int(input("Enter the shift value: "))
            encrypted_message = encrypt(message, shift)
            print("Encrypted message:", encrypted_message)
        elif choice == 'd':
            message = input("Enter the message to decrypt: ")
            shift = int(input("Enter the shift value: "))
            decrypted_message = decrypt(message, shift)
            print("Decrypted message:", decrypted_message)
        else:
            print("Invalid choice. Please enter 'e', 'd', or 'q'.")


if __name__ == "__main__":
    main()
