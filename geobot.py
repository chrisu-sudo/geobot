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
from typing import Optional, List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging
import sys

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
    ttl: int = 0

# ---- Setup ----
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

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

# DNS library availability check
HAS_DNSPYTHON = False
try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
    logger.info("dnspython available - full DNS features enabled")
except ImportError:
    logger.warning("dnspython not available - using basic DNS resolution")

# ---- Advanced IP Validation ----
def validate_ip(ip: str) -> bool:
    """Advanced IP validation supporting IPv4 and IPv6"""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

# ---- Advanced IP Lookup ----
async def advanced_ip_lookup(ip: str) -> Optional[IPInfo]:
    """Fetch comprehensive IP information from multiple sources"""
    cache_key = f"ip_{ip}"
    current_time = datetime.now().timestamp()
    
    if cache_key in cache and (current_time - cache[cache_key]['time']) < 3600:
        return IPInfo(**cache[cache_key]['data'])
    
    try:
        async with aiohttp.ClientSession() as session:
            # Try multiple IP APIs for redundancy
            apis = [
                f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,timezone,lat,lon,mobile,proxy,query",
                f"http://ipinfo.io/{ip}/json?token=",  # Note: requires token for full features
                f"https://ipapi.co/{ip}/json/"
            ]
            
            for api_url in apis:
                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with session.get(api_url, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            # Handle different API response formats
                            if "status" in data and data["status"] == "success":
                                # ip-api.com format
                                info = IPInfo(
                                    ip=data.get("query", ip),
                                    country=data.get("country", "N/A"),
                                    region=data.get("regionName", "N/A"),
                                    city=data.get("city", "N/A"),
                                    isp=data.get("isp", "N/A"),
                                    org=data.get("org", "N/A"),
                                    asn=data.get("as", "N/A"),
                                    timezone=data.get("timezone", "N/A"),
                                    lat=float(data.get("lat", 0.0)),
                                    lon=float(data.get("lon", 0.0)),
                                    mobile=data.get("mobile", False),
                                    proxy=data.get("proxy", False)
                                )
                                cache[cache_key] = {'data': vars(info), 'time': current_time}
                                return info
                            elif "country" in data:
                                # Generic format
                                info = IPInfo(
                                    ip=ip,
                                    country=data.get("country", "N/A"),
                                    region=data.get("region", "N/A"),
                                    city=data.get("city", "N/A"),
                                    isp=data.get("org", data.get("isp", "N/A")),
                                    org=data.get("org", "N/A"),
                                    asn=data.get("asn", "N/A"),
                                    timezone=data.get("timezone", "N/A"),
                                    lat=float(data.get("latitude", data.get("lat", 0.0))),
                                    lon=float(data.get("longitude", data.get("lon", 0.0))),
                                    mobile=False,
                                    proxy=data.get("proxy", False)
                                )
                                cache[cache_key] = {'data': vars(info), 'time': current_time}
                                return info
                except Exception as api_error:
                    logger.debug(f"API {api_url} failed: {api_error}")
                    continue
                    
    except Exception as e:
        logger.error(f"IP lookup error for {ip}: {e}")
    
    return None

# ---- Fallback DNS Lookup ----
async def basic_dns_lookup(domain: str) -> List[DNSRecord]:
    """Basic DNS resolution without dnspython"""
    records = []
    
    try:
        # A Record
        try:
            ip = await asyncio.get_event_loop().run_in_executor(
                executor, lambda: socket.gethostbyname(domain)
            )
            records.append(DNSRecord(type='A', value=ip))
        except socket.gaierror:
            pass
            
        # Reverse DNS
        try:
            reverse = await asyncio.get_event_loop().run_in_executor(
                executor, lambda: socket.gethostbyaddr(ip)[0] if 'ip' in locals() else None
            )
            if reverse:
                records.append(DNSRecord(type='PTR', value=reverse))
        except:
            pass
            
        # MX Records (using dig subprocess as fallback)
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                executor, lambda: subprocess.run(
                    ['dig', '+short', 'MX', domain],
                    capture_output=True, text=True, timeout=10
                )
            )
            if result.returncode == 0 and result.stdout.strip():
                mx_records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
                for mx in mx_records[:3]:  # Limit to 3 MX records
                    records.append(DNSRecord(type='MX', value=mx))
        except:
            pass
            
    except Exception as e:
        logger.error(f"Basic DNS lookup error for {domain}: {e}")
    
    return records

# ---- Advanced DNS with dnspython ----
async def comprehensive_dns_lookup(domain: str) -> List[DNSRecord]:
    """Perform complete DNS resolution using dnspython if available"""
    if not HAS_DNSPYTHON:
        return await basic_dns_lookup(domain)
    
    records = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    records.append(DNSRecord(
                        type=rtype,
                        value=str(rdata).rstrip('.'),
                        ttl=answers.rrset.ttl if hasattr(answers, 'rrset') else 0
                    ))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                continue
                
        # Reverse lookup
        try:
            a_records = resolver.resolve(domain, 'A')
            for a_record in a_records:
                try:
                    reverse_domain = dns.reversename.from_address(str(a_record))
                    reverse = str(resolver.resolve(reverse_domain, 'PTR')[0]).rstrip('.')
                    records.append(DNSRecord(type='PTR', value=reverse))
                except:
                    pass
        except:
            pass
            
    except Exception as e:
        logger.error(f"Advanced DNS lookup error for {domain}: {e}")
        return await basic_dns_lookup(domain)  # Fallback
    
    return records

# ---- Advanced Ping ----
async def advanced_ping(host: str, count: int = 4) -> Dict:
    """Multi-protocol ping testing"""
    results = {
        'http': {'success': False, 'latency': None, 'status': None},
        'tcp': {'success': False, 'latency': None, 'port': None},
        'dns': {'success': False, 'latency': None}
    }
    
    # HTTP Ping
    try:
        start_time = datetime.now()
        connector = aiohttp.TCPConnector(limit=1, limit_per_host=1)
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(f"http://{host}", allow_redirects=False) as resp:
                latency = (datetime.now() - start_time).total_seconds() * 1000
                results['http'] = {
                    'success': resp.status < 500,
                    'latency': round(latency, 2),
                    'status': resp.status
                }
    except:
        try:
            # Try HTTPS
            start_time = datetime.now()
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{host}", timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                    latency = (datetime.now() - start_time).total_seconds() * 1000
                    results['http'] = {
                        'success': resp.status < 500,
                        'latency': round(latency, 2),
                        'status': resp.status
                    }
        except:
            pass
    
    # TCP Ping
    for port in [80, 443, 22]:
        try:
            start_time = datetime.now()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0
            )
            latency = (datetime.now() - start_time).total_seconds() * 1000
            writer.close()
            await writer.wait_closed()
            results['tcp'] = {'success': True, 'latency': round(latency, 2), 'port': port}
            break
        except:
            continue
    
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

# ---- Port Check Utility ----
async def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

# ---- Events ----
@bot.event
async def on_ready():
    print(f"✅ {bot.user} is now online!")
    logger.info(f"Bot connected to {len(bot.guilds)} guilds")
    logger.info(f"DNS features: {'Full (dnspython)' if HAS_DNSPYTHON else 'Basic'}")
    cleanup_cache.start()

@tasks.loop(hours=1)
async def cleanup_cache():
    """Clean expired cache entries"""
    current_time = datetime.now().timestamp()
    expired = [k for k, v in list(cache.items()) 
               if (current_time - v['time']) > 3600]
    for key in expired:
        del cache[key]
    if expired:
        logger.info(f"Cleaned {len(expired)} expired cache entries")

# ---- Commands ----

@bot.command(name='iplookup', aliases=['ip', 'whois'])
@commands.cooldown(1, 5, commands.BucketType.user)
async def ip_lookup(ctx, *, target: str = None):
    """Advanced IP geolocation"""
    if not target:
        await ctx.send("⚠️ **Usage**: `!iplookup <IP>` Example: `!iplookup 8.8.8.8`")
        return
    
    # Try to resolve domain to IP
    ip = target
    if not validate_ip(target):
        try:
            await ctx.send(f"🔄 Resolving `{target}` to IP...")
            ip = await asyncio.get_event_loop().run_in_executor(
                executor, lambda: socket.gethostbyname(target)
            )
        except socket.gaierror:
            await ctx.send(f"❌ Invalid IP or unresolvable domain: `{target}`")
            return
    
    if not validate_ip(ip):
        await ctx.send(f"❌ Invalid IP format: `{ip}`")
        return
    
    await ctx.send(f"🔍 Analyzing IP `{ip}`...")
    
    info = await advanced_ip_lookup(ip)
    if not info:
        await ctx.send(f"❌ Could not retrieve information for `{ip}`")
        return
    
    embed = discord.Embed(
        title=f"🌍 IP Intelligence: {info.ip}", 
        color=0x00ff88, 
        timestamp=datetime.now()
    )
    
    location = f"{info.city}, {info.region}, {info.country}"
    embed.add_field(name="📍 Location", value=location or "N/A", inline=True)
    embed.add_field(name="🌐 ISP", value=info.isp or "N/A", inline=True)
    embed.add_field(name="🏢 Organization", value=info.org or "N/A", inline=True)
    embed.add_field(name="🕐 Timezone", value=info.timezone or "N/A", inline=True)
    
    security = []
    if info.proxy:
        security.append("🔒 **Proxy/VPN**: Detected")
    if info.mobile:
        security.append("📱 **Mobile**: Detected")
    embed.add_field(name="🔐 Security", value="\n".join(security) or "✅ Clean", inline=False)
    
    coords = f"{info.lat}, {info.lon}"
    if info.lat != 0.0 and info.lon != 0.0:
        map_url = f"https://maps.googleapis.com/maps/api/staticmap?center={info.lat},{info.lon}&zoom=10&size=400x300&maptype=roadmap&markers=color:red%7Clabel:P%7C{info.lat},{info.lon}&key="
        embed.set_image(url=map_url)
        embed.add_field(name="📊 Coordinates", value=f"`{coords}`", inline=True)
    
    embed.set_footer(text="Powered by multiple IP intelligence APIs")
    await ctx.send(embed=embed)

@bot.command(name='dns', aliases=['dig'])
@commands.cooldown(1, 10, commands.BucketType.user)
async def dns_lookup(ctx, *, domain: str = None):
    """Comprehensive DNS resolution"""
    if not domain:
        await ctx.send("⚠️ **Usage**: `!dns <domain>` Example: `!dns google.com`")
        return
    
    await ctx.send(f"🔍 Resolving DNS records for `{domain}`...")
    
    records = await comprehensive_dns_lookup(domain)
    if not records:
        await ctx.send(f"❌ No DNS records found for `{domain}`")
        return
    
    embed = discord.Embed(
        title=f"🔎 DNS Records: {domain}", 
        color=0x0099ff, 
        timestamp=datetime.now()
    )
    
    # Group records by type
    grouped = {}
    for record in records:
        rtype = record.type
        if rtype not in grouped:
            grouped[rtype] = []
        grouped[rtype].append(record.value)
    
    for rtype, values in grouped.items():
        display_values = values[:10]  # Limit display
        value_str = '\n'.join(display_values)
        if len(values) > 10:
            value_str += f"\n... and {len(values) - 10} more"
        
        embed.add_field(
            name=f"📋 {rtype} ({len(values)})",
            value=f"```{value_str}```" if value_str else "No data",
            inline=False
        )
    
    dns_type = "Full Analysis" if HAS_DNSPYTHON else "Basic Resolution"
    embed.set_footer(text=f"{dns_type} • {len(records)} total records")
    await ctx.send(embed=embed)

@bot.command(name='ping', aliases=['latency'])
@commands.cooldown(1, 3, commands.BucketType.user)
async def ping_host(ctx, host: str = None):
    """Multi-protocol connectivity test"""
    if not host:
        await ctx.send("⚠️ **Usage**: `!ping <host>` Example: `!ping google.com`")
        return
    
    await ctx.send(f"🏓 Testing connectivity to `{host}`...")
    
    results = await advanced_ping(host)
    
    embed = discord.Embed(title=f"🏓 Connectivity Test: {host}", color=0x00ff00)
    
    # HTTP
    http = results['http']
    http_text = f"✅ {http['latency']}ms (HTTP {http['status']})" if http['success'] else "❌ Failed"
    embed.add_field(name="🌐 HTTP", value=http_text, inline=True)
    
    # TCP
    tcp = results['tcp']
    tcp_text = f"✅ {tcp['latency']}ms (Port {tcp['port']})" if tcp['success'] else "❌ Failed"
    embed.add_field(name="🔌 TCP", value=tcp_text, inline=True)
    
    # DNS
    dns = results['dns']
    dns_text = f"✅ {dns['latency']}ms" if dns['success'] else "❌ Failed"
    embed.add_field(name="🔍 DNS", value=dns_text, inline=True)
    
    # Summary
    success_count = sum(1 for r in results.values() if r['success'])
    status = "🟢 Excellent" if success_count == 3 else "🟡 Good" if success_count == 2 else "🔴 Poor"
    embed.add_field(name="📊 Summary", value=f"{status}\n{success_count}/3 protocols OK", inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='portscan', aliases=['ports'])
@commands.cooldown(1, 15, commands.BucketType.user)
async def port_scan(ctx, host: str = None, *, ports: str = "80,443,22,21,25,53"):
    """Scan common ports"""
    if not host:
        await ctx.send("⚠️ **Usage**: `!portscan <host> [ports]`")
        return
    
    try:
        port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
    except ValueError:
        await ctx.send("❌ Invalid port numbers")
        return
    
    if not port_list:
        port_list = [80, 443, 22, 21, 25, 53, 3306]
    
    await ctx.send(f"🔍 Scanning {len(port_list)} ports on `{host}`...")
    
    open_ports = []
    tasks = [check_port(host, port) for port in port_list]
    
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if result is True:
                open_ports.append(port_list[i])
    except Exception:
        pass
    
    color = 0x00ff00 if open_ports else 0xff4444
    status = "🟢" if open_ports else "🔴"
    
    embed = discord.Embed(
        title=f"🔌 Port Scan: {host}",
        description=f"{status} **{len(open_ports)}/{len(port_list)} ports open**",
        color=color
    )
    
    if open_ports:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis"
        }
        port_info = []
        for port in sorted(open_ports):
            service = services.get(port, "Unknown")
            port_info.append(f"{port} ({service})")
        
        embed.add_field(
            name="📋 Open Ports",
            value="```" + "\n".join(port_info) + "```",
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command(name='netinfo')
async def network_info(ctx):
    """Bot network information"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ipify.org?format=json', timeout=10) as resp:
                if resp.status == 200:
                    public_ip = (await resp.json())['ip']
                else:
                    public_ip = "Unable to fetch"
        
        sys_info = platform.uname()
        
        embed = discord.Embed(title="🌐 Bot Network Info", color=0x0099ff)
        embed.add_field(name="🌍 Public IP", value=public_ip, inline=True)
        embed.add_field(name="💻 System", value=sys_info.system, inline=True)
        embed.add_field(name="🐧 OS", value=f"{sys_info.release} {sys_info.version}", inline=True)
        embed.add_field(name="🔗 Connected", value=f"{len(bot.guilds)} guilds", inline=True)
        embed.add_field(name="🛠️ DNS Mode", value="Full" if HAS_DNSPYTHON else "Basic", inline=True)
        
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='help', aliases=['h'])
async def help_command(ctx):
    embed = discord.Embed(
        title="🛠️ Advanced Network Toolkit", 
        description="Professional networking diagnostics",
        color=0x00ff00
    )
    embed.add_field(
        name="🌍 **IP Analysis**",
        value="`!iplookup <ip/domain>` - Geolocation & threat intel",
        inline=False
    )
    embed.add_field(
        name="🔍 **DNS**",
        value="`!dns <domain>` - A, MX, NS, TXT records" + 
        (" (Full)" if HAS_DNSPYTHON else " (Basic)"),
        inline=False
    )
    embed.add_field(
        name="🏓 **Connectivity**",
        value="`!ping <host>` - HTTP/TCP/DNS testing\n`!portscan <host>` - Port scanning",
        inline=False
    )
    embed.add_field(
        name="ℹ️ **Info**",
        value="`!netinfo` - Bot system info\n`!help` - This menu",
        inline=False
    )
    embed.set_footer(text="Rate limited • Secure • Cached")
    await ctx.send(embed=embed)

# ---- Error Handling ----
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("⚠️ Missing argument. Use `!help` for usage.")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Cooldown: {error.retry_after:.1f}s")
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Invalid argument format.")
    else:
        logger.error(f"Command error: {error}")
        await ctx.send("❌ An unexpected error occurred.")

# ---- Run Bot ----
if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("❌ DISCORD_TOKEN environment variable not required.")
    
    # Auto-install dependencies on Render
    dependencies = ["aiohttp"]
    if not HAS_DNSPYTHON:
        dependencies.append("dnspython")
    
    try:
        for dep in dependencies:
            subprocess.run([sys.executable, "-m", "pip", "install", dep, "--quiet"], 
                          capture_output=True, check=True)
        print(f"✅ Installed dependencies: {', '.join(dependencies)}")
    except subprocess.CalledProcessError:
        print("⚠️ Could not auto-install dependencies - ensure they're in requirements.txt")
    
    # Restart DNS check after potential install
    if not HAS_DNSPYTHON:
        try:
            import dns.resolver
            HAS_DNSPYTHON = True
            print("✅ dnspython now available after install")
        except ImportError:
            print("ℹ️ Using basic DNS features (no dnspython)")
    
    bot.run(token)