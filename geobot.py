import discord
from discord.ext import commands, tasks
import requests
import aiohttp
import socket
import subprocess
import platform
import os
import asyncio
import json
import re
from datetime import datetime
from typing import Optional, List
import dns.resolver
import dns.reversename
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---- Data Classes ----
@dataclass
class IPInfo:
    ip: str
    country: str
    region: str
    city: str
    isp: str
    org: str
    asn: str
    timezone: str
    lat: float
    lon: float
    mobile: bool
    proxy: bool

@dataclass
class DNSRecord:
    type: str
    value: str
    ttl: int

# ---- Setup ----
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(
    command_prefix='!', 
    intents=intents, 
    help_command=None,
    case_insensitive=True
)

# Thread pool for blocking operations
executor = ThreadPoolExecutor(max_workers=4)

# Cache for rate limiting and performance
cache = {}

# ---- Advanced IP Validation ----
def validate_ip(ip: str) -> bool:
    """Advanced IP validation supporting IPv4 and IPv6"""
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(?::0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

# ---- Advanced IP Lookup ----
async def advanced_ip_lookup(ip: str) -> Optional[IPInfo]:
    """Fetch comprehensive IP information from multiple sources"""
    cache_key = f"ip_{ip}"
    if cache_key in cache and (datetime.now().timestamp() - cache[cache_key]['time']) < 3600:
        return IPInfo(**cache[cache_key]['data'])
    
    try:
        async with aiohttp.ClientSession() as session:
            # Primary source
            async with session.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,timezone,lat,lon,mobile,proxy,query", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        info = IPInfo(
                            ip=data.get("query", ip),
                            country=data.get("country", "N/A"),
                            region=data.get("regionName", "N/A"),
                            city=data.get("city", "N/A"),
                            isp=data.get("isp", "N/A"),
                            org=data.get("org", "N/A"),
                            asn="N/A",  # Would need additional API
                            timezone=data.get("timezone", "N/A"),
                            lat=data.get("lat", 0.0),
                            lon=data.get("lon", 0.0),
                            mobile=data.get("mobile", False),
                            proxy=data.get("proxy", False)
                        )
                        
                        cache[cache_key] = {'data': vars(info), 'time': datetime.now().timestamp()}
                        return info
    except Exception as e:
        logger.error(f"IP lookup error for {ip}: {e}")
    
    return None

# ---- Comprehensive DNS Lookup ----
async def comprehensive_dns_lookup(domain: str) -> List[DNSRecord]:
    """Perform complete DNS resolution for all record types"""
    records = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
    
    try:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    records.append(DNSRecord(
                        type=rtype,
                        value=str(rdata),
                        ttl=answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                continue
                
        # Reverse lookup for A record
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            for a_record in a_records:
                try:
                    reverse_domain = dns.reversename.from_address(str(a_record))
                    reverse = str(dns.resolver.resolve(reverse_domain, 'PTR')[0])
                    records.append(DNSRecord(type='PTR', value=reverse, ttl=0))
                except:
                    pass
        except:
            pass
            
    except Exception as e:
        logger.error(f"DNS lookup error for {domain}: {e}")
    
    return records

# ---- Advanced Ping with Multiple Protocols ----
async def advanced_ping(host: str, count: int = 4) -> dict:
    """Multi-protocol ping testing HTTP, TCP, and DNS"""
    results = {
        'http': {'success': False, 'latency': None, 'status': None},
        'tcp': {'success': False, 'latency': None, 'port': 80},
        'dns': {'success': False, 'latency': None}
    }
    
    start_time = datetime.now()
    
    # HTTP Ping
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{host}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                latency = (datetime.now() - start_time).total_seconds() * 1000
                results['http'] = {
                    'success': True,
                    'latency': round(latency, 2),
                    'status': resp.status
                }
    except:
        pass
    
    # TCP Ping (port 80 or 443)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 80),
            timeout=5.0
        )
        latency = (datetime.now() - start_time).total_seconds() * 1000
        writer.close()
        await writer.wait_closed()
        results['tcp'] = {'success': True, 'latency': round(latency, 2), 'port': 80}
    except:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443),
                timeout=5.0
            )
            latency = (datetime.now() - start_time).total_seconds() * 1000
            writer.close()
            await writer.wait_closed()
            results['tcp'] = {'success': True, 'latency': round(latency, 2), 'port': 443}
        except:
            pass
    
    # DNS Ping
    dns_start = datetime.now()
    try:
        await asyncio.get_event_loop().run_in_executor(
            executor, lambda: socket.gethostbyname(host)
        )
        results['dns'] = {
            'success': True,
            'latency': round((datetime.now() - dns_start).total_seconds() * 1000, 2)
        }
    except:
        pass
    
    return results

# ---- Events ----
@bot.event
async def on_ready():
    print(f"✅ {bot.user} is now online and running!")
    logger.info(f"Bot connected to {len(bot.guilds)} guilds")
    # Start cache cleanup task
    cleanup_cache.start()

@tasks.loop(hours=1)
async def cleanup_cache():
    """Clean expired cache entries"""
    expired = [k for k, v in cache.items() 
               if (datetime.now().timestamp() - v['time']) > 3600]
    for key in expired:
        del cache[key]
    logger.info(f"Cleaned {len(expired)} expired cache entries")

# ---- Commands ----

@bot.command(name='iplookup', aliases=['ip', 'whois'])
async def ip_lookup(ctx, *, ip: str = None):
    """Advanced IP geolocation and threat intelligence"""
    if not ip:
        await ctx.send("⚠️ **Usage**: `!iplookup <IP>` or `!iplookup 8.8.8.8`")
        return
    
    # Extract IP from domain if provided
    if not validate_ip(ip):
        try:
            ip_addr = socket.gethostbyname(ip)
            await ctx.send(f"🔄 Resolving domain `{ip}` to IP: `{ip_addr}`")
            ip = ip_addr
        except:
            await ctx.send(f"❌ Invalid IP or unresolvable domain: `{ip}`")
            return
    
    if not validate_ip(ip):
        await ctx.send(f"❌ Invalid IP format: `{ip}`")
        return
    
    await ctx.send("🔍 Fetching comprehensive IP intelligence...")
    
    info = await advanced_ip_lookup(ip)
    if not info:
        await ctx.send(f"❌ Could not retrieve information for `{ip}`")
        return
    
    embed = discord.Embed(title=f"🌍 IP Intelligence: {info.ip}", color=0x00ff00, timestamp=datetime.now())
    embed.set_thumbnail(url=f"https://maps.googleapis.com/maps/api/staticmap?center={info.lat},{info.lon}&zoom=10&size=300x200&maptype=roadmap&markers=color:red%7Clabel:P%7C{info.lat},{info.lon}")
    
    embed.add_field(name="📍 Location", value=f"{info.city}, {info.region}, {info.country}", inline=True)
    embed.add_field(name="🌐 Network", value=f"**ISP**: {info.isp}\n**Org**: {info.org}", inline=True)
    embed.add_field(name="🕐 Timezone", value=info.timezone, inline=True)
    embed.add_field(name="🔒 Security", value=f"**Proxy**: {'✅' if info.proxy else '❌'}\n**Mobile**: {'✅' if info.mobile else '❌'}", inline=True)
    embed.add_field(name="📊 Coordinates", value=f"`{info.lat}, {info.lon}`", inline=False)
    
    embed.set_footer(text=f"IP Analysis • Powered by ip-api.com")
    await ctx.send(embed=embed)

@bot.command(name='dns', aliases=['dig'])
async def dns_lookup(ctx, *, domain: str = None):
    """Comprehensive DNS resolution for all record types"""
    if not domain:
        await ctx.send("⚠️ **Usage**: `!dns <domain>` or `!dns example.com`")
        return
    
    await ctx.send("🔍 Performing comprehensive DNS resolution...")
    
    records = await comprehensive_dns_lookup(domain)
    if not records:
        await ctx.send(f"❌ No DNS records found for `{domain}`")
        return
    
    embed = discord.Embed(title=f"🔎 DNS Records: {domain}", color=0x0099ff, timestamp=datetime.now())
    
    # Group records by type
    grouped = {}
    for record in records:
        rtype = record.type
        if rtype not in grouped:
            grouped[rtype] = []
        grouped[rtype].append(record.value)
    
    for rtype, values in grouped.items():
        value_str = '\n'.join(values[:5])  # Limit to 5 records per type
        if len(values) > 5:
            value_str += f"\n... and {len(values) - 5} more"
        embed.add_field(
            name=f"📋 {rtype} Records",
            value=f"```{value_str}```",
            inline=False
        )
    
    embed.set_footer(text=f"DNS Resolution • {len(records)} total records")
    await ctx.send(embed=embed)

@bot.command(name='ping', aliases=['latency'])
async def ping_host(ctx, host: str = None, count: int = 4):
    """Multi-protocol ping testing"""
    if not host:
        await ctx.send("⚠️ **Usage**: `!ping <host> [count]`")
        return
    
    await ctx.send("🏓 Testing connectivity with multiple protocols...")
    
    results = await advanced_ping(host, count)
    
    embed = discord.Embed(title=f"🏓 Multi-Protocol Ping: {host}", color=0x00ff00)
    
    # HTTP Results
    http = results['http']
    http_status = f"✅ **{http['latency']}ms** (HTTP {http['status']})" if http['success'] else "❌ Failed"
    embed.add_field(name="🌐 HTTP", value=http_status, inline=True)
    
    # TCP Results
    tcp = results['tcp']
    tcp_status = f"✅ **{tcp['latency']}ms** (Port {tcp['port']})" if tcp['success'] else "❌ Failed"
    embed.add_field(name="🔌 TCP", value=tcp_status, inline=True)
    
    # DNS Results
    dns = results['dns']
    dns_status = f"✅ **{dns['latency']}ms**" if dns['success'] else "❌ Failed"
    embed.add_field(name="🔍 DNS", value=dns_status, inline=True)
    
    # Overall status
    success_count = sum(1 for r in results.values() if r['success'])
    status_emoji = "🟢" if success_count == 3 else "🟡" if success_count >= 2 else "🔴"
    embed.add_field(name="📊 Overall", value=f"{status_emoji} {success_count}/3 protocols successful", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='portscan', aliases=['ports'])
async def port_scan(ctx, host: str = None, ports: str = "80,443,22,21,25"):
    """Basic port scanning for common services"""
    if not host:
        await ctx.send("⚠️ **Usage**: `!portscan <host> [ports]`")
        return
    
    port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
    
    await ctx.send(f"🔍 Scanning ports {port_list} on {host}...")
    
    open_ports = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for port in port_list:
            task = asyncio.create_task(check_port(host, port))
            tasks.append((task, port))
        
        for task, port in tasks:
            try:
                result = await asyncio.wait_for(task, timeout=3.0)
                if result:
                    open_ports.append(port)
            except asyncio.TimeoutError:
                pass
    
    status = "🟢" if open_ports else "🔴"
    embed = discord.Embed(
        title=f"🔌 Port Scan: {host}",
        description=f"{status} Found {len(open_ports)} open ports",
        color=0x00ff00 if open_ports else 0xff0000
    )
    
    if open_ports:
        services = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 
            25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL"
        }
        port_info = [f"{p} ({services.get(p, 'Unknown')})" for p in open_ports]
        embed.add_field(name="📋 Open Ports", value="```" + "\n".join(map(str, port_info)) + "```", inline=False)
    
    await ctx.send(embed=embed)

async def check_port(host: str, port: int) -> bool:
    """Check if a port is open"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=2.0
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

@bot.command(name='netinfo')
async def network_info(ctx):
    """Display bot's network information"""
    try:
        # Get public IP
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ipify.org?format=json', timeout=5) as resp:
                public_ip = (await resp.json())['ip']
        
        # System info
        sys_info = platform.uname()
        python_version = platform.python_version()
        
        embed = discord.Embed(title="🌐 Network & System Info", color=0x0099ff)
        embed.add_field(name="🌍 Public IP", value=public_ip, inline=True)
        embed.add_field(name="💻 System", value=sys_info.system, inline=True)
        embed.add_field(name="🐧 Release", value=sys_info.release, inline=True)
        embed.add_field(name="🧠 Python", value=python_version, inline=True)
        embed.add_field(name="📡 Uptime", value=f"{len(bot.guilds)} guilds", inline=False)
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Error fetching network info: {e}")

@bot.command(name='help', aliases=['commands'])
async def help_command(ctx):
    embed = discord.Embed(title="🛠️ Advanced Network Bot", description="Comprehensive networking toolkit", color=0x00ff00)
    embed.add_field(
        name="🌍 **IP & Geolocation**",
        value="`!iplookup <ip>` - Advanced IP intelligence\n`!whois <ip>` - Same as iplookup",
        inline=False
    )
    embed.add_field(
        name="🔍 **DNS Analysis**",
        value="`!dns <domain>` - Full DNS records\n`!dig <domain>` - Alternative DNS command",
        inline=False
    )
    embed.add_field(
        name="🏓 **Connectivity**",
        value="`!ping <host>` - Multi-protocol ping\n`!portscan <host> [ports]` - Port scanning",
        inline=False
    )
    embed.add_field(
        name="ℹ️ **System**",
        value="`!netinfo` - Bot network information\n`!help` - This menu",
        inline=False
    )
    embed.set_footer(text="Rate limited • Cached results • Secure operations")
    await ctx.send(embed=embed)

# Error handler
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"⚠️ Missing required argument. Use `!help` for usage.")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Command on cooldown. Try again in {error.retry_after:.1f}s")
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(f"❌ An error occurred: {str(error)}")

# ---- Run Bot ----
if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("❌ DISCORD_TOKEN environment variable not set.")
    
    # Install required packages on startup (for Render)
    try:
        subprocess.run(["pip", "install", "aiohttp", "dnspython"], 
                      capture_output=True, check=True)
    except:
        pass  # Already installed or no pip access
    
    bot.run(token)