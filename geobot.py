import discord
from discord.ext import commands
import requests
import socket
import subprocess
import platform
import os

# ---- Setup ----
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)


# ---- Events ----
@bot.event
async def on_ready():
    print(f"✅ {bot.user} is now online and running on Render!")


# ---- IP Lookup ----
@bot.command(name='iplookup')
async def ip_lookup(ctx, ip: str = None):
    if not ip:
        await ctx.send("⚠️ Please provide an IP. Example: `!iplookup 8.8.8.8`")
        return

    try:
        socket.inet_aton(ip)
    except socket.error:
        await ctx.send(f"❌ Invalid IP format: `{ip}`")
        return

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data.get("status") != "success":
            await ctx.send(f"❌ Could not find info for `{ip}`")
            return

        embed = discord.Embed(title=f"🌍 IP Lookup: {ip}", color=discord.Color.blue())
        embed.add_field(name="Country", value=data.get("country", "N/A"))
        embed.add_field(name="City", value=data.get("city", "N/A"))
        embed.add_field(name="Region", value=data.get("regionName", "N/A"))
        embed.add_field(name="ISP", value=data.get("isp", "N/A"), inline=False)
        embed.add_field(name="Timezone", value=data.get("timezone", "N/A"))
        embed.add_field(name="Org", value=data.get("org", "N/A"), inline=False)

        await ctx.send(embed=embed)

    except requests.exceptions.Timeout:
        await ctx.send("❌ Request timed out.")
    except Exception as e:
        await ctx.send(f"❌ Error: `{e}`")


# ---- DNS ----
@bot.command(name='dns')
async def dns_lookup(ctx, domain: str = None):
    if not domain:
        await ctx.send("⚠️ Please provide a domain. Example: `!dns example.com`")
        return

    try:
        ip = socket.gethostbyname(domain)
        try:
            reverse = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            reverse = "N/A"

        embed = discord.Embed(title=f"🔎 DNS Lookup: {domain}", color=discord.Color.blue())
        embed.add_field(name="IP Address", value=ip, inline=False)
        embed.add_field(name="Reverse DNS", value=reverse, inline=False)
        await ctx.send(embed=embed)

    except socket.gaierror:
        await ctx.send(f"❌ Could not resolve domain `{domain}`")
    except Exception as e:
        await ctx.send(f"❌ Error: `{e}`")


# ---- Ping ----
@bot.command(name='ping')
async def ping_host(ctx, host: str = None):
    if not host:
        await ctx.send("⚠️ Please provide a host. Example: `!ping google.com`")
        return

    try:
        # Render blocks raw ICMP, so we'll simulate ping with requests
        try:
            response = requests.get(f"http://{host}", timeout=5)
            latency = round(response.elapsed.total_seconds() * 1000, 2)
            embed = discord.Embed(
                title=f"🏓 HTTP Ping: {host}",
                description=f"✅ Response in `{latency} ms` (HTTP 200 OK)",
                color=discord.Color.green(),
            )
            await ctx.send(embed=embed)
        except requests.exceptions.Timeout:
            await ctx.send(f"❌ Timeout reaching `{host}`")
        except requests.exceptions.RequestException as e:
            await ctx.send(f"❌ Unable to reach `{host}` — {str(e)}")

    except Exception as e:
        await ctx.send(f"❌ Error: `{e}`")


# ---- Traceroute ----
@bot.command(name='traceroute')
async def traceroute_host(ctx, host: str = None):
    if not host:
        await ctx.send("⚠️ Please provide a host. Example: `!traceroute google.com`")
        return

    try:
        # Some Render instances restrict traceroute, so this may fail
        cmd = ['traceroute', '-m', '10', host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = result.stdout or "No output"
        if len(output) > 3900:
            output = output[:3900] + "\n... (truncated)"
        embed = discord.Embed(
            title=f"🛰️ Traceroute: {host}",
            description=f"```\n{output}\n```",
            color=discord.Color.green(),
        )
        await ctx.send(embed=embed)
    except subprocess.TimeoutExpired:
        await ctx.send("❌ Traceroute timed out.")
    except Exception as e:
        await ctx.send(f"❌ Error: `{e}`")


# ---- Help ----
@bot.command(name='help')
async def help_command(ctx):
    embed = discord.Embed(title="📘 IP Utility Bot Commands", color=discord.Color.gold())
    embed.add_field(name="!iplookup <ip>", value="Get detailed info about an IP", inline=False)
    embed.add_field(name="!ping <host>", value="HTTP ping a domain/IP", inline=False)
    embed.add_field(name="!dns <domain>", value="Lookup DNS records", inline=False)
    embed.add_field(name="!traceroute <host>", value="Trace network hops to a host", inline=False)
    await ctx.send(embed=embed)


# ---- Run Bot ----
token = os.getenv("DISCORD_TOKEN")
if not token:
    raise SystemExit("❌ ERROR: DISCORD_TOKEN environment variable not set on Render.")
bot.run(token)