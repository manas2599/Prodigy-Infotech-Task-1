from PIL import Image

def encrypt_image(image_path, key):
    img = Image.open(image_path)
    width, height = img.size
    encrypted_pixels = []

    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            encrypted_pixel = tuple((p + key) % 256 for p in pixel)
            encrypted_pixels.append(encrypted_pixel)

    encrypted_img = Image.new(img.mode, (width, height))
    encrypted_img.putdata(encrypted_pixels)
    encrypted_img.save("encrypted_image.png")
    print("Image encrypted successfully!")

def decrypt_image(image_path, key):
    img = Image.open(image_path)
    width, height = img.size
    decrypted_pixels = []

    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            decrypted_pixel = tuple((p - key) % 256 for p in pixel)
            decrypted_pixels.append(decrypted_pixel)

    decrypted_img = Image.new(img.mode, (width, height))
    decrypted_img.putdata(decrypted_pixels)
    decrypted_img.save("decrypted_image.png")
    print("Image decrypted successfully!")

def main():
    while True:
        choice = input("Enter 'e' to encrypt or 'd' to decrypt (q to quit): ").lower()
        if choice == 'q':
            break
        elif choice == 'e':
            image_path = input("Enter the path to the image to encrypt: ")
            key = int(input("Enter the encryption key (an integer): "))
            encrypt_image(image_path, key)
        elif choice == 'd':
            image_path = input("Enter the path to the image to decrypt: ")
            key = int(input("Enter the decryption key (an integer): "))
            decrypt_image(image_path, key)
        else:
            print("Invalid choice. Please enter 'e', 'd', or 'q'.")

if __name__ == "__main__":
    main()
