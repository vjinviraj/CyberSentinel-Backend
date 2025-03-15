import requests
from bs4 import BeautifulSoup
import json
import re
import whois
import dns.resolver
import socket
import datetime
import time
import argparse
import urllib.parse
from urllib.parse import urlparse
import ipaddress
import favicon
import ssl
import socket

class WebsiteInfoScraper:
    def __init__(self, url):
        # Ensure URL has proper format
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.url = url
        self.domain = urlparse(url).netloc
        self.results = {
            "url": url,
            "domain": self.domain,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        try:
            self.response = requests.get(url, timeout=10)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except Exception as e:
            self.response = None
            self.soup = None
            self.results["error"] = str(e)
    
    def check_using_ip(self):
        """Check if the URL uses an IP address instead of a domain name"""
        parsed = urlparse(self.url)
        hostname = parsed.netloc.split(':')[0]  # Remove port if present
        
        try:
            # Try to parse the hostname as an IP address
            ipaddress.ip_address(hostname)
            return {
                "Using_ip": True,
                "ip_address": hostname
            }
        except ValueError:
            # If it fails, it's not a valid IP address
            return {
                "Using_ip": False
            }
    
    def check_url_length(self):
        """Analyze URL length to determine if it's unusually long or short"""
        url_length = len(self.url)
        
        return {
            "url_length": url_length,
            "is_long_url": url_length > 75,
            "is_short_url": url_length < 20
        }
    
    def check_at_symbol(self):
        """Check if the URL contains @ symbol, which can be used for deception"""
        has_at_symbol = '@' in self.url
        
        # If @ exists, find its position and what's before/after it
        if has_at_symbol:
            at_position = self.url.find('@')
            before_at = self.url[:at_position]
            after_at = self.url[at_position+1:]
        else:
            at_position = None
            before_at = None
            after_at = None
        
        return {
            "has_@_symbol": has_at_symbol,
            "at_position": at_position,
            "before_at": before_at,
            "after_at": after_at
        }
    
    def check_redirecting_symbols(self):
        """Check for URL redirecting symbols like //"""
        parsed = urlparse(self.url)
        path = parsed.path
        
        # Check for double slash in the path (not counting the protocol part)
        has_double_slash = '//' in path
        
        # Check for excessive redirects
        max_redirects = 5
        redirect_count = 0
        redirect_chain = []
        current_url = self.url
        
        try:
            response = requests.head(self.url, allow_redirects=True, timeout=10)
            redirect_chain = [h.url for h in response.history]
            redirect_count = len(redirect_chain)
            final_url = response.url
        except:
            redirect_count = 0
            redirect_chain = []
            final_url = self.url
        
        return {
            "has_double_slash_in_path": has_double_slash,
            "redirect_count": redirect_count,
            "has_excessive_redirects": redirect_count > max_redirects,
            "redirect_chain": redirect_chain,
            "final_url": final_url
        }
    
    def check_prefix_suffix(self):
        """Check for hyphens and other prefixes/suffixes in domain"""
        parsed = urlparse(self.url)
        domain_name = parsed.netloc.split(':')[0]  # Remove port if present
        
        # Check for hyphens in domain
        hyphen_count = domain_name.count('-')
        
        # Check common deceptive prefixes/suffixes
        common_prefixes = ['secure-', 'login-', 'verify-', 'account-', 'update-']
        common_suffixes = ['-secure', '-login', '-verify', '-account', '-update']
        
        found_prefixes = [prefix for prefix in common_prefixes if domain_name.startswith(prefix)]
        found_suffixes = [suffix for suffix in common_suffixes if domain_name.endswith(suffix)]
        
        return {
            "hyphen_count": hyphen_count,
            "has_suspicious_prefix": len(found_prefixes) > 0,
            "suspicious_prefixes": found_prefixes,
            "has_suspicious_suffix": len(found_suffixes) > 0,
            "suspicious_suffixes": found_suffixes
        }
    
    def check_subdomains(self):
        """Analyze subdomains in the URL"""
        parsed = urlparse(self.url)
        domain_parts = parsed.netloc.split(':')[0].split('.')
        
        # Count the number of subdomains
        if len(domain_parts) > 2:
            subdomains = domain_parts[:-2]  # Everything except domain and TLD
            subdomain_count = len(subdomains)
            subdomain_string = '.'.join(subdomains)
        else:
            subdomains = []
            subdomain_count = 0
            subdomain_string = ""
        
        # Check for excessive subdomains
        excessive_subdomains = subdomain_count > 3
        
        return {
            "has_subdomains": subdomain_count > 0,
            "subdomain_count": subdomain_count,
            "subdomains": subdomains,
            "subdomain_string": subdomain_string,
            "excessive_subdomains": excessive_subdomains
        }
    
    def check_info_email(self):
        """Check for information or contact emails on the page"""
        if not self.soup:
            return {"emails_found": 0, "emails": []}
        
        # Combined regex for different email formats
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, self.response.text)
        
        # Look for specific contact emails
        contact_emails = []
        for email in emails:
            if any(prefix in email.lower() for prefix in ['info', 'contact', 'support', 'admin', 'help']):
                contact_emails.append(email)
        
        # Deduplicate
        unique_emails = list(set(emails))
        unique_contact_emails = list(set(contact_emails))
        
        return {
            "emails_found": len(unique_emails),
            "emails": unique_emails,
            "contact_emails_found": len(unique_contact_emails),
            "contact_emails": unique_contact_emails
        }
    
    def check_favicon(self):
        """Check favicon information"""
        if not self.soup:
            return {"favicon_found": False}
        
        favicon_found = False
        favicon_url = None
        favicon_domain = None
        favicon_mismatch = False
        
        try:
            # Look for favicon link
            favicon_link = self.soup.find("link", rel=lambda r: r and ("icon" in r.lower() or "shortcut" in r.lower()))
            
            if favicon_link and favicon_link.get('href'):
                favicon_found = True
                href = favicon_link.get('href')
                
                # Handle relative URLs
                if href.startswith('//'):
                    favicon_url = 'https:' + href
                elif href.startswith('/'):
                    favicon_url = f"{urlparse(self.url).scheme}://{self.domain}{href}"
                elif not href.startswith(('http://', 'https://')):
                    favicon_url = f"{urlparse(self.url).scheme}://{self.domain}/{href}"
                else:
                    favicon_url = href
                
                # Check if favicon is from a different domain
                favicon_domain = urlparse(favicon_url).netloc
                if favicon_domain and favicon_domain != self.domain:
                    favicon_mismatch = True
            
            # If no favicon link found, try the default location
            else:
                default_favicon = f"{urlparse(self.url).scheme}://{self.domain}/favicon.ico"
                try:
                    favicon_response = requests.head(default_favicon, timeout=5)
                    if favicon_response.status_code == 200:
                        favicon_found = True
                        favicon_url = default_favicon
                        favicon_domain = self.domain
                        favicon_mismatch = False
                except:
                    pass
        
        except Exception as e:
            return {
                "favicon_found": False,
                "error": str(e)
            }
        
        return {
            "favicon_found": favicon_found,
            "favicon_url": favicon_url,
            "favicon_domain": favicon_domain,
            "favicon_domain_mismatch": favicon_mismatch
        }
    
    def check_https(self):
        """Check HTTPS usage and certificate information"""
        parsed = urlparse(self.url)
        is_https = parsed.scheme == 'https'
        
        cert_info = {}
        if is_https:
            try:
                # Get certificate information
                hostname = parsed.netloc.split(':')[0]  # Remove port if present
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract relevant certificate info
                        issued_to = dict(x[0] for x in cert['subject'])
                        issued_by = dict(x[0] for x in cert['issuer'])
                        
                        cert_info = {
                            "common_name": issued_to.get('commonName'),
                            "organization": issued_to.get('organizationName'),
                            "issuer": issued_by.get('commonName'),
                            "valid_from": cert.get('notBefore'),
                            "valid_until": cert.get('notAfter'),
                            "alt_names": cert.get('subjectAltName', [])
                        }
            except Exception as e:
                cert_info = {
                    "error": str(e)
                }
        
        return {
            "is_https": is_https,
            "certificate": cert_info if is_https else None
        }
    
    def check_anchor_url(self):
        """Analyze anchor elements and their href attributes"""
        if not self.soup:
            return {"anchors_count": 0, "external_links": 0, "relative_links": 0}
        
        anchors = self.soup.find_all('a')
        external_count = 0
        relative_count = 0
        
        for anchor in anchors:
            href = anchor.get('href')
            if href:
                if href.startswith(('http://', 'https://')) and self.domain not in href:
                    external_count += 1
                elif href.startswith('/') or href.startswith('#'):
                    relative_count += 1
        
        return {
            "anchors_count": len(anchors),
            "external_links": external_count,
            "relative_links": relative_count
        }
    
    def check_links_in_script_tags(self):
        """Find links in script tags"""
        if not self.soup:
            return {"script_tags_count": 0, "external_scripts": 0}
        
        scripts = self.soup.find_all('script')
        external_scripts = 0
        
        for script in scripts:
            src = script.get('src')
            if src and src.startswith(('http://', 'https://')) and self.domain not in src:
                external_scripts += 1
        
        return {
            "script_tags_count": len(scripts),
            "external_scripts": external_scripts
        }
    
    def check_server_form_handler(self):
        """Check form handlers and where they point to"""
        if not self.soup:
            return {"forms_count": 0, "external_form_handlers": 0}
        
        forms = self.soup.find_all('form')
        external_handlers = 0
        
        for form in forms:
            action = form.get('action', '')
            if action and action.startswith(('http://', 'https://')) and self.domain not in action:
                external_handlers += 1
        
        return {
            "forms_count": len(forms),
            "external_form_handlers": external_handlers
        }
    
    def extract_emails(self):
        """Extract email addresses from page content"""
        if not self.response:
            return {"emails": []}
        
        # Simple regex for email extraction
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, self.response.text)
        
        # Remove duplicates
        unique_emails = list(set(emails))
        
        return {"emails": unique_emails}
    
    def check_abnormal_url(self):
        """Check for abnormal URL characteristics"""
        abnormal_features = []
        parsed = urlparse(self.url)
        
        # Check for IP address instead of domain
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, parsed.netloc):
            abnormal_features.append("IP_as_domain")
        
        # Check for excessive subdomains
        if len(parsed.netloc.split('.')) > 3:
            abnormal_features.append("excessive_subdomains")
            
        # Check for unusual TLD
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io']
        has_common_tld = any(parsed.netloc.endswith(tld) for tld in common_tlds)
        if not has_common_tld:
            abnormal_features.append("uncommon_tld")
            
        # Check for unusual port
        if parsed.port and parsed.port not in [80, 443]:
            abnormal_features.append(f"unusual_port_{parsed.port}")
            
        # Check for very long domain
        if len(parsed.netloc) > 40:
            abnormal_features.append("long_domain")
            
        # Special characters in domain (excluding hyphens and dots)
        domain_without_port = parsed.netloc.split(':')[0]
        special_chars = re.findall(r'[^a-zA-Z0-9.-]', domain_without_port)
        if special_chars:
            abnormal_features.append("special_chars_in_domain")
        
        return {
            "is_abnormal": len(abnormal_features) > 0,
            "abnormal_features": abnormal_features
        }
    
    def check_website_forwarding(self):
        """Check if website uses redirection"""
        if not self.response:
            return {"has_redirection": False}
        
        initial_url = self.url
        final_url = self.response.url
        
        return {
            "has_redirection": initial_url != final_url,
            "initial_url": initial_url,
            "final_url": final_url if initial_url != final_url else None
        }
    
    def check_status_bar_customization(self):
        """Check for JavaScript that might modify status bar"""
        if not self.soup:
            return {"status_bar_manipulation": False}
        
        scripts = self.soup.find_all('script')
        status_bar_manipulation = False
        
        for script in scripts:
            script_content = script.string if script.string else ""
            if "window.status" in script_content or "onmouseover" in script_content:
                status_bar_manipulation = True
                break
                
        # Also check for onmouseover attributes that might change status bar
        elements_with_mouseover = self.soup.select('[onmouseover]')
        for element in elements_with_mouseover:
            if "window.status" in element.get('onmouseover', ''):
                status_bar_manipulation = True
                break
        
        return {"status_bar_manipulation": status_bar_manipulation}
    
    def check_disable_right_click(self):
        """Check if the page disables right-click"""
        if not self.soup:
            return {"right_click_disabled": False}
        
        right_click_disabled = False
        
        # Check oncontextmenu in body or html
        body = self.soup.find('body')
        html = self.soup.find('html')
        
        if body and 'oncontextmenu' in body.attrs:
            right_click_disabled = True
        elif html and 'oncontextmenu' in html.attrs:
            right_click_disabled = True
            
        # Check scripts for right-click prevention
        scripts = self.soup.find_all('script')
        for script in scripts:
            script_content = script.string if script.string else ""
            if "oncontextmenu" in script_content and "return false" in script_content:
                right_click_disabled = True
                break
        
        return {"right_click_disabled": right_click_disabled}
    
    def check_using_popup_window(self):
        """Check if the page uses popup windows"""
        if not self.soup:
            return {"uses_popups": False}
        
        scripts = self.soup.find_all('script')
        uses_popups = False
        
        popup_indicators = ['window.open', 'popup', 'open(']
        
        for script in scripts:
            script_content = script.string if script.string else ""
            if any(indicator in script_content for indicator in popup_indicators):
                uses_popups = True
                break
        
        return {"uses_popups": uses_popups}
    
    def check_iframe_redirection(self):
        """Check for iframes that might be used for redirection"""
        if not self.soup:
            return {"iframe_count": 0, "hidden_iframes": 0}
        
        iframes = self.soup.find_all('iframe')
        hidden_iframes = 0
        
        for iframe in iframes:
            style = iframe.get('style', '')
            if 'display: none' in style or 'visibility: hidden' in style:
                hidden_iframes += 1
            elif iframe.get('height', '') == '0' or iframe.get('width', '') == '0':
                hidden_iframes += 1
        
        return {
            "iframe_count": len(iframes),
            "hidden_iframes": hidden_iframes
        }
    
    def check_age_of_domain(self):
        """Check domain registration information"""
        try:
            w = whois.whois(self.domain)
            
            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            # Calculate age
            if creation_date:
                today = datetime.datetime.now()
                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
                    except:
                        return {"domain_info_available": False}
                
                age_days = (today - creation_date).days
                age_years = age_days / 365.25
                
                return {
                    "domain_info_available": True,
                    "creation_date": creation_date.strftime("%Y-%m-%d"),
                    "expiration_date": w.expiration_date[0].strftime("%Y-%m-%d") if isinstance(w.expiration_date, list) else 
                                      w.expiration_date.strftime("%Y-%m-%d") if w.expiration_date else None,
                    "age_days": age_days,
                    "age_years": round(age_years, 2)
                }
            else:
                return {"domain_info_available": False}
        except:
            return {"domain_info_available": False}
    
    def check_dns_records(self):
        """Get DNS records for the domain"""
        try:
            # Get A record
            a_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                for rdata in answers:
                    a_records.append(str(rdata))
            except:
                pass
            
            # Get MX record
            mx_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                for rdata in answers:
                    mx_records.append(str(rdata.exchange))
            except:
                pass
            
            # Get NS record
            ns_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                for rdata in answers:
                    ns_records.append(str(rdata))
            except:
                pass
            
            return {
                "dns_available": True,
                "a_records": a_records,
                "mx_records": mx_records,
                "ns_records": ns_records
            }
        except:
            return {"dns_available": False}
    
    def generate_basic_stats(self):
        """Generate basic website statistics"""
        if not self.soup or not self.response:
            return {
                "page_size_kb": 0,
                "load_time_ms": 0,
                "element_count": 0
            }
        
        # Calculate page size
        page_size_kb = len(self.response.content) / 1024
        
        # Count all HTML elements
        all_elements = self.soup.find_all()
        
        return {
            "page_size_kb": round(page_size_kb, 2),
            "element_count": len(all_elements),
            "status_code": self.response.status_code,
            "content_type": self.response.headers.get('Content-Type', 'unknown')
        }
    
    def check_links_pointing_to_page(self):
        """Return placeholder for backlink data"""
        # Note: Actual backlink data would require external APIs
        return {
            "note": "Backlink information requires external APIs or services",
            "estimated_backlinks": "unknown"
        }
    
    def check_website_traffic(self):
        """Return placeholder for traffic data"""
        # Note: Actual traffic data would require external APIs
        return {
            "note": "Traffic information requires external APIs or services",
            "estimated_monthly_visits": "unknown"
        }
    
    def check_page_rank(self):
        """Return placeholder for page rank data"""
        # Note: PageRank is no longer publicly available
        return {
            "note": "PageRank is no longer publicly available"
        }
    
    def check_google_index(self):
        """Return placeholder for Google index data"""
        # Note: Checking Google indexing requires search API
        return {
            "note": "Google index information requires search API",
            "estimated_indexed_pages": "unknown"
        }
    
    def collect_all_info(self):
        """Collect all website information"""
        # Original features
        self.results["AnchorURL"] = self.check_anchor_url()
        self.results["LinksInScriptTags"] = self.check_links_in_script_tags()
        self.results["ServerFormHandler"] = self.check_server_form_handler()
        self.results["InfoEmail"] = self.extract_emails()
        self.results["AbnormalURL"] = self.check_abnormal_url()
        self.results["WebsiteForwarding"] = self.check_website_forwarding()
        self.results["StatusBarCust"] = self.check_status_bar_customization()
        self.results["DisableRightClick"] = self.check_disable_right_click()
        self.results["UsingPopupWindow"] = self.check_using_popup_window()
        self.results["IframeRedirection"] = self.check_iframe_redirection()
        self.results["AgeofDomain"] = self.check_age_of_domain()
        self.results["DNSRecording"] = self.check_dns_records()
        self.results["WebsiteTraffic"] = self.check_website_traffic()
        self.results["PageRank"] = self.check_page_rank()
        self.results["GoogleIndex"] = self.check_google_index()
        self.results["LinksPointingToPage"] = self.check_links_pointing_to_page()
        self.results["StatsReport"] = self.generate_basic_stats()
        
        # New features
        self.results["UsingIP"] = self.check_using_ip()
        self.results["LongURL"] = self.check_url_length()
        self.results["Symbol@"] = self.check_at_symbol()
        self.results["Redirecting//"] = self.check_redirecting_symbols()
        self.results["PrefixSuffix-"] = self.check_prefix_suffix()
        self.results["SubDomains"] = self.check_subdomains()
        self.results["Favicon"] = self.check_favicon()
        self.results["HTTPS"] = self.check_https()
        
        return self.results
    
    def export_to_json(self, filename=None):
        """Export results to JSON file"""
        if not filename:
            filename = f"{self.domain.replace('.','-')}_scan_{int(time.time())}.json"
        
        with open(filename, 'w') as json_file:
            json.dump(self.results, json_file, indent=4)
        
        return filename


def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(description='Website Information Scraper')
    parser.add_argument('url', help='URL of the website to analyze')
    parser.add_argument('-o', '--output', help='Output JSON filename')
    args = parser.parse_args()
    
    # Initialize and run the scraper
    print(f"Analyzing website: {args.url}")
    scraper = WebsiteInfoScraper(args.url)
    results = scraper.collect_all_info()
    
    # Export to JSON
    output_file = scraper.export_to_json(args.output)
    print(f"Analysis complete! Results saved to: {output_file}")
    
    # Print summary
    print("\nSummary:")
    print(f"Domain: {results['domain']}")
    if "error" in results:
        print(f"Error: {results['error']}")
    else:
        print(f"Page size: {results['StatsReport']['page_size_kb']} KB")
        print(f"Elements: {results['StatsReport']['element_count']}")
        print(f"HTTPS: {'Yes' if results['HTTPS']['is_https'] else 'No'}")
        print(f"Using IP: {'Yes' if results['UsingIP']['Using_ip'] else 'No'}")
        print(f"URL Length: {results['LongURL']['url_length']} chars")
        if results['AgeofDomain']['domain_info_available']:
            print(f"Domain age: {results['AgeofDomain']['age_years']} years")
        if results['AbnormalURL']['is_abnormal']:
            print(f"Abnormal URL features: {', '.join(results['AbnormalURL']['abnormal_features'])}")


if __name__ == "__main__":
    main()