import discord
from discord.ext import commands, tasks
import aiohttp
import socket
import subprocess
import platform
import os
import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging
import sys
import ssl
import ipaddress
import base64
from io import BytesIO
import matplotlib.pyplot as plt  # For subnet visualization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
    hosting: bool = False
    threat_level: str = "Low"

@dataclass
class DNSRecord:
    type: str
    value: str
    ttl: int = 0
    priority: int = 0

@dataclass
class WhoisInfo:
    domain: str
    registrar: str
    creation_date: str
    expiration_date: str
    name_servers: List[str]
    status: str
    emails: List[str]

@dataclass
class SSLInfo:
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    serial_number: str
    version: int
    signature_algorithm: str
    days_to_expiry: int

# ---- Setup ----
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(
    command_prefix='!', 
    intents=intents, 
    help_command=None,
    case_insensitive=True,
    activity=discord.Activity(type=discord.ActivityType.watching, name="networks 🔍"),
    status=discord.Status.dnd
)

# Thread pool for blocking operations
executor = ThreadPoolExecutor(max_workers=8)

# Cache with TTL
class TTLCache:
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self.cache: Dict[str, Tuple[any, float]] = {}
    
    def get(self, key: str) -> Optional[any]:
        if key in self.cache:
            value, timestamp = self.cache[key]
            if (datetime.now().timestamp() - timestamp) < self.ttl:
                return value
        return None
    
    def set(self, key: str, value: any):
        self.cache[key] = (value, datetime.now().timestamp())

cache = TTLCache(ttl=3600)

# Library availability checks
HAS_DNSPYTHON = False
HAS_WHOIS = False
HAS_CRYPTO = False

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    pass

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    pass

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    pass

# ---- Utility Functions ----
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

async def resolve_target(target: str) -> Tuple[Optional[str], str]:
    """Resolve target to IP and type (ip or domain)"""
    if validate_ip(target):
        return target, "ip"
    elif validate_domain(target):
        try:
            ip = await asyncio.get_event_loop().run_in_executor(
                executor, socket.gethostbyname, target
            )
            return ip, "domain"
        except:
            return None, "invalid"
    return None, "invalid"

# ---- Advanced IP Lookup with Threat Intel ----
async def advanced_ip_lookup(ip: str) -> Optional[IPInfo]:
    cache_key = f"ip_{ip}"
    cached = cache.get(cache_key)
    if cached:
        return IPInfo(**cached)
    
    apis = [
        (f"http://ip-api.com/json/{ip}?fields=66846719", "ip-api"),  # All fields except offset
        (f"https://ipapi.co/{ip}/json/", "ipapi"),
        (f"http://ipwho.is/{ip}", "ipwhois")
    ]
    
    for url, source in apis:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("success", True):
                            # Normalize data
                            info = IPInfo(
                                ip=data.get("ip", data.get("query", ip)),
                                country=data.get("country_name", data.get("country", "N/A")),
                                region=data.get("region_name", data.get("region", "N/A")),
                                city=data.get("city", "N/A"),
                                isp=data.get("isp", data.get("org", "N/A")),
                                org=data.get("org", data.get("organisation", "N/A")),
                                asn=data.get("asn", "N/A"),
                                timezone=data.get("timezone", "N/A"),
                                lat=float(data.get("latitude", 0.0)),
                                lon=float(data.get("longitude", 0.0)),
                                mobile=data.get("mobile", False),
                                proxy=data.get("proxy", data.get("vpn", False)),
                                hosting=data.get("hosting", data.get("datacenter", False)),
                                threat_level="Medium" if data.get("proxy", False) or data.get("hosting", False) else "Low"
                            )
                            cache.set(cache_key, vars(info))
                            logger.info(f"IP lookup from {source} for {ip}")
                            return info
        except Exception as e:
            logger.debug(f"{source} API failed for {ip}: {e}")
    
    return None

# ---- Advanced DNS Lookup ----
async def comprehensive_dns_lookup(domain: str) -> List[DNSRecord]:
    cache_key = f"dns_{domain}"
    cached = cache.get(cache_key)
    if cached:
        return [DNSRecord(**rec) for rec in cached]
    
    records = []
    if HAS_DNSPYTHON:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    priority = 0
                    value = str(rdata)
                    if rtype == 'MX':
                        parts = value.split()
                        if len(parts) == 2:
                            priority = int(parts[0])
                            value = parts[1].rstrip('.')
                    records.append(DNSRecord(rtype, value.rstrip('.'), answers.rrset.ttl, priority))
            except:
                pass
    else:
        # Basic fallback
        try:
            addrinfo = await asyncio.get_event_loop().run_in_executor(
                executor, socket.getaddrinfo, domain, None
            )
            for _, _, _, _, sockaddr in addrinfo:
                ip = sockaddr[0]
                records.append(DNSRecord('A' if ':' not in ip else 'AAAA', ip))
        except:
            pass
        
        # MX fallback with dig
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                executor, subprocess.run, ['dig', '+short', 'MX', domain], {'capture_output': True, 'text': True, 'timeout': 5}
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) == 2:
                            records.append(DNSRecord('MX', parts[1].rstrip('.'), priority=int(parts[0])))
        except:
            pass
    
    if records:
        cache.set(cache_key, [vars(rec) for rec in records])
    
    return records

# ---- Whois Lookup ----
async def whois_lookup(domain: str) -> Optional[WhoisInfo]:
    cache_key = f"whois_{domain}"
    cached = cache.get(cache_key)
    if cached:
        return WhoisInfo(**cached)
    
    if HAS_WHOIS:
        try:
            w = await asyncio.get_event_loop().run_in_executor(
                executor, whois.whois, domain
            )
            info = WhoisInfo(
                domain=w.domain or domain,
                registrar=w.registrar or "N/A",
                creation_date=str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or "N/A"),
                expiration_date=str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or "N/A"),
                name_servers=w.name_servers or [],
                status=w.status or "N/A",
                emails=w.emails or []
            )
            cache.set(cache_key, vars(info))
            return info
        except:
            pass
    else:
        # Fallback with subprocess whois
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                executor, subprocess.run, ['whois', domain], {'capture_output': True, 'text': True, 'timeout': 10}
            )
            if result.returncode == 0:
                output = result.stdout
                # Parse basic info
                registrar = re.search(r'Registrar:\s*(.+)', output, re.I)
                creation = re.search(r'Creation Date:\s*(.+)', output, re.I)
                expiration = re.search(r'Expiration Date:\s*(.+)', output, re.I)
                ns = re.findall(r'Name Server:\s*(.+)', output, re.I)
                status = re.search(r'Status:\s*(.+)', output, re.I)
                emails = re.findall(r'[\w\.-]+@[\w\.-]+', output)
                
                info = WhoisInfo(
                    domain=domain,
                    registrar=registrar.group(1) if registrar else "N/A",
                    creation_date=creation.group(1) if creation else "N/A",
                    expiration_date=expiration.group(1) if expiration else "N/A",
                    name_servers=ns,
                    status=status.group(1) if status else "N/A",
                    emails=list(set(emails))
                )
                cache.set(cache_key, vars(info))
                return info
        except:
            pass
    
    return None

# ---- SSL Certificate Info ----
async def get_ssl_info(host: str, port: int = 443) -> Optional[SSLInfo]:
    cache_key = f"ssl_{host}:{port}"
    cached = cache.get(cache_key)
    if cached:
        return SSLInfo(**cached)
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssl.DER_cert_to_PEM_cert(cert_der)
                
                if HAS_CRYPTO:
                    x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
                    subject = str(x509_cert.subject)
                    issuer = str(x509_cert.issuer)
                    valid_from = x509_cert.not_valid_before.isoformat()
                    valid_to = x509_cert.not_valid_after.isoformat()
                    serial = x509_cert.serial_number
                    version = x509_cert.version.value
                    sig_algo = x509_cert.signature_hash_algorithm.name
                else:
                    # Basic parsing
                    cert_dict = ssock.getpeercert()
                    subject = cert_dict.get('subjectAltName', [('DNS', host)])[0][1]
                    issuer = cert_dict['issuer'][0][0][1]
                    valid_from = cert_dict['notBefore']
                    valid_to = cert_dict['notAfter']
                    serial = cert_dict['serialNumber']
                    version = cert_dict['version']
                    sig_algo = "Unknown"
                
                days_to_expiry = (datetime.fromisoformat(valid_to) - datetime.now()).days
                
                info = SSLInfo(
                    subject=subject,
                    issuer=issuer,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    serial_number=str(serial),
                    version=version,
                    signature_algorithm=sig_algo,
                    days_to_expiry=days_to_expiry
                )
                cache.set(cache_key, vars(info))
                return info
    except Exception as e:
        logger.debug(f"SSL info failed for {host}:{port}: {e}")
        return None

# ---- Subnet Calculator ----
def subnet_calculator(cidr: str) -> Dict:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            'network': str(network.network_address),
            'broadcast': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'wildcard': str(network.hostmask),
            'hosts': network.num_addresses - 2 if network.num_addresses > 2 else 0,
            'prefix': network.prefixlen,
            'range': f"{str(network.network_address + 1)} - {str(network.broadcast_address - 1)}" if network.num_addresses > 2 else "N/A"
        }
    except ValueError:
        return {}

def generate_subnet_visual(cidr: str) -> Optional[str]:
    info = subnet_calculator(cidr)
    if not info:
        return None
    
    fig, ax = plt.subplots(figsize=(8, 2))
    ax.axis('off')
    ax.text(0.5, 0.8, f"Subnet: {cidr}", ha='center', fontweight='bold')
    ax.text(0.5, 0.6, f"Network: {info['network']}", ha='center')
    ax.text(0.5, 0.4, f"Usable: {info['range']}", ha='center')
    ax.text(0.5, 0.2, f"Hosts: {info['hosts']}", ha='center')
    
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    plt.close()
    return base64.b64encode(buf.read()).decode('utf-8')

# ---- Advanced Ping ----
async def advanced_ping(host: str, count: int = 3) -> Dict:
    results = {'latencies': [], 'packet_loss': 0, 'protocols': {}}
    
    for _ in range(count):
        start = datetime.now()
        try:
            await asyncio.get_event_loop().run_in_executor(
                executor, socket.gethostbyname, host
            )
            latency = (datetime.now() - start).total_seconds() * 1000
            results['latencies'].append(latency)
        except:
            results['packet_loss'] += 1
    
    # Protocol tests...
    # (keep similar to previous, but add more stats)
    
    if results['latencies']:
        results['avg_latency'] = sum(results['latencies']) / len(results['latencies'])
        results['min_latency'] = min(results['latencies'])
        results['max_latency'] = max(results['latencies'])
    return results

# ---- Events ----
@bot.event
async def on_ready():
    print(f"✅ {bot.user} is online! Advanced mode enabled.")
    logger.info(f"Connected to {len(bot.guilds)} guilds")
    logger.info(f"Features: DNS={'Advanced' if HAS_DNSPYTHON else 'Basic'}, Whois={'Advanced' if HAS_WHOIS else 'Basic'}, Crypto={'Advanced' if HAS_CRYPTO else 'Basic'}")
    cleanup_cache.start()

@tasks.loop(minutes=30)
async def cleanup_cache():
    # Cache cleanup is handled by TTLCache, but can add more
    pass

# ---- Commands ----
@bot.command(name='iplookup', aliases=['ip', 'geoip'])
@commands.cooldown(2, 10, commands.BucketType.user)
async def ip_lookup(ctx, *, target: str):
    ip, target_type = await resolve_target(target)
    if target_type == "invalid":
        return await ctx.send("❌ Invalid IP or domain.")
    
    info = await advanced_ip_lookup(ip)
    if not info:
        return await ctx.send("❌ Lookup failed.")
    
    embed = discord.Embed(title=f"🌍 IP Intelligence: {info.ip}", color=0x1E90FF)
    embed.add_field(name="📍 Location", value=f"{info.city}, {info.region}, {info.country}", inline=False)
    embed.add_field(name="🌐 Provider", value=f"ISP: {info.isp}\nOrg: {info.org}\nASN: {info.asn}", inline=False)
    embed.add_field(name="🕒 Timezone", value=info.timezone, inline=True)
    embed.add_field(name="📡 Type", value=f"Mobile: {'Yes' if info.mobile else 'No'}\nHosting: {'Yes' if info.hosting else 'No'}", inline=True)
    embed.add_field(name="🔒 Security", value=f"Proxy: {'Detected' if info.proxy else 'None'}\nThreat: {info.threat_level}", inline=False)
    if info.lat and info.lon:
        embed.set_thumbnail(url=f"https://maps.googleapis.com/maps/api/staticmap?center={info.lat},{info.lon}&zoom=12&size=400x200&markers=color:blue%7C{info.lat},{info.lon}")
    await ctx.send(embed=embed)

@bot.command(name='dns', aliases=['resolve'])
@commands.cooldown(2, 10, commands.BucketType.user)
async def dns_lookup(ctx, *, domain: str):
    if not validate_domain(domain):
        return await ctx.send("❌ Invalid domain.")
    
    records = await comprehensive_dns_lookup(domain)
    if not records:
        return await ctx.send("❌ No records found.")
    
    embed = discord.Embed(title=f"🔎 DNS Records for {domain}", color=0x00BFFF)
    grouped = {}
    for rec in records:
        grouped.setdefault(rec.type, []).append(rec)
    
    for rtype, recs in grouped.items():
        values = [f"{rec.priority} {rec.value}" if rec.priority else rec.value for rec in recs]
        embed.add_field(name=f"{rtype} ({len(recs)})", value="\n".join(values[:10]), inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='whois')
@commands.cooldown(1, 15, commands.BucketType.user)
async def whois_cmd(ctx, *, domain: str):
    if not validate_domain(domain):
        return await ctx.send("❌ Invalid domain.")
    
    info = await whois_lookup(domain)
    if not info:
        return await ctx.send("❌ Whois lookup failed.")
    
    embed = discord.Embed(title=f"📋 Whois for {info.domain}", color=0x87CEEB)
    embed.add_field(name="Registrar", value=info.registrar, inline=True)
    embed.add_field(name="Created", value=info.creation_date, inline=True)
    embed.add_field(name="Expires", value=info.expiration_date, inline=True)
    embed.add_field(name="Status", value=info.status, inline=False)
    embed.add_field(name="Name Servers", value="\n".join(info.name_servers[:5]), inline=False)
    embed.add_field(name="Contacts", value="\n".join(info.emails[:3]), inline=False)
    await ctx.send(embed=embed)

@bot.command(name='ssl', aliases=['cert'])
@commands.cooldown(2, 10, commands.BucketType.user)
async def ssl_info(ctx, host: str, port: int = 443):
    info = await get_ssl_info(host, port)
    if not info:
        return await ctx.send("❌ SSL info retrieval failed.")
    
    color = 0x32CD32 if info.days_to_expiry > 30 else 0xFF4500 if info.days_to_expiry < 0 else 0xFFD700
    embed = discord.Embed(title=f"🔐 SSL Certificate for {host}:{port}", color=color)
    embed.add_field(name="Subject", value=info.subject, inline=False)
    embed.add_field(name="Issuer", value=info.issuer, inline=False)
    embed.add_field(name="Valid From", value=info.valid_from, inline=True)
    embed.add_field(name="Valid To", value=info.valid_to, inline=True)
    embed.add_field(name="Days Left", value=str(info.days_to_expiry), inline=True)
    embed.add_field(name="Serial", value=info.serial_number, inline=False)
    embed.add_field(name="Signature", value=info.signature_algorithm, inline=True)
    await ctx.send(embed=embed)

@bot.command(name='subnet', aliases=['cidr'])
@commands.cooldown(1, 5, commands.BucketType.user)
async def subnet_calc(ctx, *, cidr: str):
    info = subnet_calculator(cidr)
    if not info:
        return await ctx.send("❌ Invalid CIDR notation.")
    
    embed = discord.Embed(title=f"🖧 Subnet Calculator: {cidr}", color=0x4682B4)
    embed.add_field(name="Network", value=info['network'], inline=True)
    embed.add_field(name="Broadcast", value=info['broadcast'], inline=True)
    embed.add_field(name="Netmask", value=info['netmask'], inline=True)
    embed.add_field(name="Usable Range", value=info['range'], inline=False)
    embed.add_field(name="Hosts", value=str(info['hosts']), inline=True)
    embed.add_field(name="Prefix", value=str(info['prefix']), inline=True)
    
    visual = generate_subnet_visual(cidr)
    if visual:
        file = discord.File(BytesIO(base64.b64decode(visual)), filename="subnet.png")
        embed.set_image(url="attachment://subnet.png")
        await ctx.send(file=file, embed=embed)
    else:
        await ctx.send(embed=embed)

# Add more commands like ping, portscan, etc., from previous version...

@bot.command(name='help')
async def help_cmd(ctx):
    embed = discord.Embed(title="🛡️ Advanced Network Analyzer Bot", color=0x20B2AA)
    embed.add_field(name="🌍 IP/Geo", value="`!iplookup <ip/domain>` - Full intel", inline=False)
    embed.add_field(name="🔎 DNS", value="`!dns <domain>` - Records lookup", inline=False)
    embed.add_field(name="📋 Whois", value="`!whois <domain>` - Domain info", inline=False)
    embed.add_field(name="🔐 SSL", value="`!ssl <host> [port]` - Cert details", inline=False)
    embed.add_field(name="🖧 Subnet", value="`!subnet <cidr>` - Calculator & visual", inline=False)
    # Add others...
    embed.set_footer(text="Enterprise-grade networking diagnostics | Rate limited")
    await ctx.send(embed=embed)

# ---- Run Bot ----
if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("❌ DISCORD_TOKEN not set.")
    
    dependencies = ["aiohttp"]
    if not HAS_DNSPYTHON:
        dependencies.append("dnspython")
    if not HAS_WHOIS:
        dependencies.append("python-whois")
    if not HAS_CRYPTO:
        dependencies.append("cryptography")
    
    try:
        for dep in dependencies:
            subprocess.run([sys.executable, "-m", "pip", "install", dep], capture_output=True, check=True)
        print(f"✅ Installed: {', '.join(dependencies)}")
    except:
        print("⚠️ Auto-install failed - add to requirements.txt")
    
    # Reload imports after install
    if "dnspython" in dependencies:
        try:
            import dns.resolver
            import dns.reversename
            HAS_DNSPYTHON = True
        except:
            pass
    if "python-whois" in dependencies:
        try:
            import whois
            HAS_WHOIS = True
        except:
            pass
    if "cryptography" in dependencies:
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            HAS_CRYPTO = True
        except:
            pass
    
    bot.run(token)