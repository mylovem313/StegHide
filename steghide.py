import argparse
import base64
import os
import cv2
from PIL import Image
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def encrypt_message(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    data = salt + nonce + ciphertext
    return base64.b64encode(data).decode()

def decrypt_message(encoded: str, password: str) -> str:
    try:
        data = base64.b64decode(encoded)
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        raise ValueError("Wrong password or corrupted data.")

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def hide_in_image(image_path, message, password, output_path="output.png"):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    if password:
        message = encrypt_message(message, password)
    bits = text_to_bits(message) + '1111111111111110'
    pixels = list(img.getdata())
    new_pixels = []
    bit_idx = 0
    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)
    print(f"[+] Hidden message saved to {output_path}")

def extract_from_image(image_path, password):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = list(img.getdata())
    bits = ''
    for pixel in pixels:
        for color in pixel:
            bits += str(color & 1)
            if bits.endswith('1111111111111110'):
                message_bits = bits[:-16]
                message = bits_to_text(message_bits)
                if password:
                    try:
                        message = decrypt_message(message, password)
                    except Exception:
                        print("[-] Wrong password or corrupted data.")
                        return
                print("[+] Message extracted:")
                print(message)
                return
    print("[-] No hidden message found.")

def video_to_frames(video_path, frames_dir):
    os.makedirs(frames_dir, exist_ok=True)
    vidcap = cv2.VideoCapture(video_path)
    count = 0
    while True:
        success, image = vidcap.read()
        if not success:
            break
        cv2.imwrite(f"{frames_dir}/frame{count:04d}.png", image)
        count += 1
    return count

def frames_to_video(frames_dir, output_path, fps=30):
    images = sorted([img for img in os.listdir(frames_dir) if img.endswith(".png")])
    if not images:
        return
    first_frame = cv2.imread(os.path.join(frames_dir, images[0]))
    height, width, _ = first_frame.shape
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    for img in images:
        frame = cv2.imread(os.path.join(frames_dir, img))
        out.write(frame)
    out.release()

def hide_in_video(video_path, message, password, output_path="output.mp4"):
    temp_dir = "temp_frames"
    frame_count = video_to_frames(video_path, temp_dir)
    if frame_count == 0:
        print("[-] No frames extracted.")
        return
    first_frame_path = os.path.join(temp_dir, "frame0000.png")
    hide_in_image(first_frame_path, message, password)
    frames_to_video(temp_dir, output_path)
    print(f"[+] Hidden message embedded in video: {output_path}")
    for f in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, f))
    os.rmdir(temp_dir)

def extract_from_video(video_path, password):
    temp_dir = "temp_extract"
    video_to_frames(video_path, temp_dir)
    first_frame_path = os.path.join(temp_dir, "frame0000.png")
    extract_from_image(first_frame_path, password)
    for f in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, f))
    os.rmdir(temp_dir)

def main():
    parser = argparse.ArgumentParser(description="Universal Steganography Tool - PNG & MP4")
    parser.add_argument('--photo', help='Path to PNG image')
    parser.add_argument('--video', help='Path to MP4 video')
    parser.add_argument('--text', help='Message to hide')
    parser.add_argument('--extract', help='Extract hidden message', action='store_true')
    parser.add_argument('--password', help='Encryption password')

    args = parser.parse_args()

    if args.photo:
        if args.extract:
            extract_from_image(args.photo, args.password)
        elif args.text:
            hide_in_image(args.photo, args.text, args.password)
        else:
            print("[-] Provide either --text or --extract with --photo")

    elif args.video:
        if args.extract:
            extract_from_video(args.video, args.password)
        elif args.text:
            hide_in_video(args.video, args.text, args.password)
        else:
            print("[-] Provide either --text or --extract with --video")
    else:
        print("[-] Please provide --photo or --video")

if __name__ == '__main__':
    main()
