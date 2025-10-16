import discord
from discord.ext import commands
import requests
import socket
import subprocess
import platform
import re
import os

# Set up the bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'{bot.user} is now running!')

@bot.command(name='iplookup')
async def ip_lookup(ctx, ip):
    """Lookup detailed info about an IP address"""
    try:
        # Validate IP format
        try:
            socket.inet_aton(ip)
        except socket.error:
            await ctx.send(f"❌ Invalid IP address format: {ip}")
            return
        
        # API request to ip-api.com
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        
        if data['status'] != 'success':
            await ctx.send(f"❌ Could not find information for IP: {ip}")
            return
        
        # Create embed with IP info
        embed = discord.Embed(title=f"IP Lookup: {ip}", color=discord.Color.blue())
        embed.add_field(name="Country", value=data.get('country', 'N/A'), inline=True)
        embed.add_field(name="City", value=data.get('city', 'N/A'), inline=True)
        embed.add_field(name="Region", value=data.get('regionName', 'N/A'), inline=True)
        embed.add_field(name="ISP", value=data.get('isp', 'N/A'), inline=False)
        embed.add_field(name="Latitude", value=data.get('lat', 'N/A'), inline=True)
        embed.add_field(name="Longitude", value=data.get('lon', 'N/A'), inline=True)
        embed.add_field(name="Timezone", value=data.get('timezone', 'N/A'), inline=True)
        embed.add_field(name="Organization", value=data.get('org', 'N/A'), inline=False)
        
        await ctx.send(embed=embed)
    except requests.exceptions.Timeout:
        await ctx.send("❌ Request timed out. Please try again.")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='ping')
async def ping_host(ctx, host):
    """Ping a domain or IP address"""
    try:
        # Determine the ping command based on OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', host]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Parse the output to get relevant info
            lines = result.stdout.split('\n')
            summary = [line for line in lines if 'min' in line or 'avg' in line or 'max' in line or 'loss' in line]
            
            output = f"```\n{result.stdout}\n```" if result.stdout else "Ping successful!"
            embed = discord.Embed(title=f"Ping: {host}", color=discord.Color.green(), description=output[:2048])
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ Could not ping {host}. Host may be unreachable.")
    except subprocess.TimeoutExpired:
        await ctx.send("❌ Ping request timed out.")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='dns')
async def dns_lookup(ctx, domain):
    """Lookup DNS records for a domain"""
    try:
        # Get IP from domain
        ip = socket.gethostbyname(domain)
        
        # Get reverse DNS
        try:
            reverse = socket.gethostbyaddr(ip)[0]
        except:
            reverse = "N/A"
        
        embed = discord.Embed(title=f"DNS Lookup: {domain}", color=discord.Color.blue())
        embed.add_field(name="IP Address", value=ip, inline=False)
        embed.add_field(name="Reverse DNS", value=reverse, inline=False)
        
        await ctx.send(embed=embed)
    except socket.gaierror:
        await ctx.send(f"❌ Could not resolve domain: {domain}")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='traceroute')
async def traceroute_host(ctx, host):
    """Traceroute to a host (Windows: tracert, Linux/Mac: traceroute)"""
    try:
        # Determine the traceroute command based on OS
        cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
        command = [cmd, '-w', '2000', host] if platform.system().lower() == 'windows' else [cmd, '-m', '15', host]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            output = result.stdout
            # Limit to first 2000 characters for Discord embed
            if len(output) > 2000:
                output = output[:1997] + "..."
            
            embed = discord.Embed(title=f"Traceroute: {host}", color=discord.Color.green(), description=f"```\n{output}\n```")
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ Traceroute failed for {host}")
    except subprocess.TimeoutExpired:
        await ctx.send("❌ Traceroute request timed out.")
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='help')
async def help_command(ctx):
    """Show all available commands"""
    embed = discord.Embed(title="IP Bot Commands", color=discord.Color.gold())
    embed.add_field(name="!iplookup <ip>", value="Get detailed geolocation info about an IP", inline=False)
    embed.add_field(name="!ping <host>", value="Ping a domain or IP address", inline=False)
    embed.add_field(name="!dns <domain>", value="Lookup DNS records for a domain", inline=False)
    embed.add_field(name="!traceroute <host>", value="Traceroute to a host", inline=False)
    await ctx.send(embed=embed)

# Run the bot with your token
bot.run(os.environ['DISCORD_TOKEN'])