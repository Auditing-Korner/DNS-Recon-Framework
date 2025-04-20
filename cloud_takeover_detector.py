#!/usr/bin/env python3
"""
Cloud Provider Subdomain Takeover Detector
This script focuses on detecting potential subdomain takeover vulnerabilities
specifically for cloud service providers.
"""

import argparse
import concurrent.futures
import dns.resolver
import json
import os
import re
import requests
import urllib3
from pathlib import Path
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from colorama import Fore, Style, init

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

@dataclass
class TakeoverResult:
    subdomain: str
    provider: str
    cname: str
    vulnerability_type: str
    evidence: str
    status_code: int
    is_vulnerable: bool
    risk_level: str = "Medium"  # Added risk level field

class CloudTakeoverDetector:
    def __init__(self, domain: str, threads: int = 10, timeout: int = 5):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Load cloud provider signatures
        self.providers = self._load_provider_signatures()
        
        # Results storage
        self.results: List[TakeoverResult] = []

    def _load_provider_signatures(self) -> Dict:
        """Load cloud provider signatures from providers.json"""
        try:
            script_dir = Path(__file__).parent
            with open(script_dir / 'providers.json', 'r') as f:
                data = json.load(f)
                return data.get('cloud_providers', [])
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading provider signatures: {e}")
            return []

    def _build_takeover_signatures(self) -> Dict[str, Dict]:
        """Build takeover signatures from provider data"""
        signatures = {}
        
        # Common takeover response patterns
        common_patterns = {
            "404_page": [
                "404 - Not Found",
                "404 Not Found",
                "Page Not Found",
                "Error 404",
                "This page does not exist",
                "The requested page could not be found",
                "Resource not available",
                "Service not available in your region"
            ],
            "no_such_service": [
                "NoSuchBucket",
                "No Such Account",
                "No Such Service",
                "Service Not Found",
                "This service is not available",
                "Service Unavailable",
                "This service has been discontinued",
                "Service not configured",
                "Resource does not exist",
                "Account suspended"
            ],
            "unclaimed": [
                "not been claimed",
                "has not been registered",
                "is not configured",
                "has not been assigned",
                "is not active",
                "not been setup",
                "pending setup",
                "domain not active",
                "resource not found",
                "service not initialized",
                "pending activation",
                "requires configuration"
            ],
            "government": [
                "government service unavailable",
                "official service not found",
                "agency not found",
                "department unavailable",
                "government resource not found",
                "official page not available",
                "federal service not configured",
                "government domain not active",
                "agency website unavailable",
                "official resource pending",
                "department service inactive",
                "government portal not found",
                "public service error",
                "government gateway timeout",
                "official system maintenance",
                "agency portal restricted",
                "government cloud error",
                "public sector service unavailable",
                "state service not configured",
                "national portal maintenance"
            ],
            "military": [
                "military service unavailable",
                "defense resource not found",
                "military domain inactive",
                "defense portal not configured",
                "military site pending setup",
                "defense service unavailable",
                "military resource not active",
                "defense website not found",
                "military cloud not configured",
                "defense platform unavailable",
                "military application error",
                "defense system offline",
                "military portal maintenance",
                "defense cloud error",
                "military service restricted",
                "classified content unavailable",
                "secure portal error",
                "restricted access error",
                "military gateway timeout",
                "defense network error"
            ],
            "isp": [
                "business service not configured",
                "enterprise portal unavailable",
                "business domain not active",
                "service provider resource not found",
                "enterprise service pending",
                "business portal not setup",
                "provider domain inactive",
                "enterprise resource unavailable"
            ]
        }
        
        for provider in self.providers:
            name = provider['name']
            signatures[name] = {
                "cname_patterns": [re.escape(domain) for domain in provider.get('dns_domains', [])],
                "signatures": common_patterns["404_page"] + 
                            common_patterns["no_such_service"] + 
                            common_patterns["unclaimed"],
                "risk_level": "Medium"  # Default risk level
            }
            
            # Add provider-specific signatures
            if name == "Amazon Web Services (AWS)":
                signatures[name]["signatures"].extend([
                    "The specified bucket does not exist",
                    "NoSuchBucket",
                    "NoSuchKey",
                    "InvalidBucketName",
                    "The specified key does not exist",
                    "The AWS Access Key Id you provided does not exist",
                    "Repository not found",
                    "Error finding repository",
                    "Failed to process your request"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Microsoft Azure":
                signatures[name]["signatures"].extend([
                    "404 Web Site not found",
                    "This web app has been stopped",
                    "This Azure Function App is not available",
                    "This Azure Static Web App has not been configured",
                    "This Azure Container App is not available",
                    "This AKS cluster is not accessible",
                    "This storage account is not accessible"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Google Cloud Platform (GCP)":
                signatures[name]["signatures"].extend([
                    "Error 404 (Not Found)",
                    "The requested URL was not found",
                    "App has not been used in a long time",
                    "Project not found",
                    "Error 404: Not Found",
                    "The requested entity was not found",
                    "Could not find backend",
                    "Backend not found",
                    "Resource not found in the API"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "GitHub Pages":
                signatures[name]["signatures"].extend([
                    "There isn't a GitHub Pages site here",
                    "For root URLs (like http://example.com/) you must provide an index.html file",
                    "Repository not found",
                    "404 File not found",
                    "Site not found",
                    "Page not found",
                    "Cannot serve this repository"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Heroku":
                signatures[name]["signatures"].extend([
                    "herokucdn.com/error-pages/no-such-app.html",
                    "No such app",
                    "Nothing to see here",
                    "Building a brand new app",
                    "Application Error",
                    "no-such-app",
                    "The app you were looking for does not exist",
                    "Heroku | No such app"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Vercel":
                signatures[name]["signatures"].extend([
                    "The deployment could not be found",
                    "404: This page could not be found",
                    "Project not found",
                    "Error: Deployment not found",
                    "Cannot find deployment",
                    "The page you're looking for doesn't exist"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Netlify":
                signatures[name]["signatures"].extend([
                    "Not found - Request ID:",
                    "Welcome to Netlify",
                    "Domain not found",
                    "Site not found",
                    "Unable to resolve this domain",
                    "This site has not been published"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "DigitalOcean":
                signatures[name]["signatures"].extend([
                    "Domain mapping does not exist",
                    "This domain is not currently being served",
                    "Domain not found in system",
                    "The requested app does not exist",
                    "Application not found",
                    "Droplet not found"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Cloudflare Pages":
                signatures[name]["signatures"].extend([
                    "Unknown Pages Site",
                    "Error 1001",
                    "Domain not configured",
                    "Page not found",
                    "Project not found",
                    "This website has not been configured"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Fastly":
                signatures[name]["signatures"].extend([
                    "Fastly error: unknown domain",
                    "Unknown domain",
                    "Fatal Error",
                    "Domain not configured",
                    "No backend configured",
                    "Service not configured properly"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Shopify":
                signatures[name]["signatures"].extend([
                    "Sorry, this shop is currently unavailable",
                    "Only store owners have access to shop",
                    "This shop is unavailable",
                    "Sorry, we couldn't find that store",
                    "Store not found",
                    "Shop has been deactivated"
                ])
                signatures[name]["risk_level"] = "High"
            
            elif name == "Squarespace":
                signatures[name]["signatures"].extend([
                    "Website Expired",
                    "You're Almost There...",
                    "This domain is not connected to a website yet",
                    "Domain Not Claimed",
                    "Account Not Available",
                    "This website has been discontinued"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Webflow":
                signatures[name]["signatures"].extend([
                    "The page you are looking for doesn't exist or has been moved",
                    "Domain not found",
                    "Site not published",
                    "Project not published",
                    "This site has not been published yet",
                    "This page is not available"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Wix":
                signatures[name]["signatures"].extend([
                    "Looks Like This Domain Isn't Connected To A Website Yet",
                    "Domain Not Connected",
                    "This website has been discontinued",
                    "This domain is not connected to a website",
                    "Connect Domain",
                    "This site hasn't been configured yet"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Pantheon":
                signatures[name]["signatures"].extend([
                    "The gods are dead",
                    "404 Unknown Site",
                    "Site Not Found",
                    "Pantheon - 404 Unknown Site",
                    "Unknown Pantheon Site",
                    "No Pantheon Site Found"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Acquia":
                signatures[name]["signatures"].extend([
                    "Site not found",
                    "Unable to connect to site",
                    "The requested website is not configured",
                    "No Acquia site found",
                    "This site is not available",
                    "Site configuration not found"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Surge.sh":
                signatures[name]["signatures"].extend([
                    "project not found",
                    "unable to serve this subdomain",
                    "404 - Not Found",
                    "This project does not exist",
                    "Project configuration not found",
                    "This domain is not serving a Surge site"
                ])
                signatures[name]["risk_level"] = "Low"
            
            elif name == "Render":
                signatures[name]["signatures"].extend([
                    "Service not found",
                    "404 not found",
                    "This service does not exist",
                    "Could not find the service you requested",
                    "This deployment does not exist",
                    "No such service exists"
                ])
                signatures[name]["risk_level"] = "Medium"
            
            elif name == "Railway":
                signatures[name]["signatures"].extend([
                    "404 Not Found",
                    "Project not found",
                    "This deployment does not exist",
                    "Service not found",
                    "No Railway service found",
                    "This domain is not configured"
                ])
                signatures[name]["risk_level"] = "Medium"

            # Add OVH Cloud
            elif name == "OVH Cloud":
                signatures[name]["signatures"].extend([
                    "This page is hosted by OVH",
                    "Domain Default page",
                    "If you're the owner of this domain",
                    "Hosted by OVH",
                    "Domain has just been created",
                    "This domain has not been activated",
                    "No website has been configured at this address",
                    "The server configuration is invalid"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Scaleway
            elif name == "Scaleway":
                signatures[name]["signatures"].extend([
                    "No service is running here",
                    "Instance not found",
                    "Resource not found on Scaleway",
                    "This Scaleway resource does not exist",
                    "Invalid instance configuration",
                    "Scaleway service not configured"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Hetzner Cloud
            elif name == "Hetzner Cloud":
                signatures[name]["signatures"].extend([
                    "Domain not configured",
                    "This domain has not been configured",
                    "No website configured at this address",
                    "Default Hetzner page",
                    "Project not found on Hetzner Cloud"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Linode
            elif name == "Linode":
                signatures[name]["signatures"].extend([
                    "This site has not yet been configured",
                    "Default Linode page",
                    "Linode domain not configured",
                    "No application configured",
                    "Instance not found"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Vultr
            elif name == "Vultr":
                signatures[name]["signatures"].extend([
                    "No website is configured at this address",
                    "Instance not found",
                    "Vultr.com - Default page",
                    "The server has not been provisioned"
                ])
                signatures[name]["risk_level"] = "High"

            # Add NATO signatures
            elif name == "NATO":
                signatures[name]["signatures"].extend([
                    "NATO service not configured",
                    "Alliance resource unavailable",
                    "NATO domain not active",
                    "Alliance portal not found",
                    "NATO site pending configuration",
                    "Military alliance service inactive"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add US Department of Defense signatures
            elif name == "US Department of Defense":
                signatures[name]["signatures"].extend([
                    "DoD resource not found",
                    "Military domain not configured",
                    "Defense service unavailable",
                    "Military portal inactive",
                    "DoD site pending setup",
                    ".mil domain not active"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add US Government signatures
            elif name == "US Government":
                signatures[name]["signatures"].extend([
                    "This .gov domain is not active",
                    "U.S. Government service not configured",
                    "Federal service unavailable",
                    "Agency website not found",
                    ".gov domain not configured",
                    "Government resource unavailable",
                    "Federal portal inactive",
                    "U.S. agency service pending"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add UK Government signatures
            elif name == "UK Government":
                signatures[name]["signatures"].extend([
                    "This .gov.uk domain is not active",
                    "UK Government service not found",
                    "Crown service unavailable",
                    "Government gateway error",
                    ".gov.uk resource not found",
                    "UK public service inactive",
                    "British government portal pending"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add EU Government signatures
            elif name == "EU Government":
                signatures[name]["signatures"].extend([
                    "Europa.eu service not found",
                    "European Union resource unavailable",
                    "EU service configuration required",
                    ".europa.eu domain not active",
                    "European Commission service inactive",
                    "EU portal not configured"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Comcast Business signatures
            elif name == "Comcast Business":
                signatures[name]["signatures"].extend([
                    "Comcast Business service not configured",
                    "Xfinity domain not found",
                    "Business service requires setup",
                    "Comcast hosting not configured",
                    "Business portal inactive"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Verizon Business signatures
            elif name == "Verizon Business":
                signatures[name]["signatures"].extend([
                    "Verizon Business not configured",
                    "Enterprise service unavailable",
                    "Verizon hosting setup required",
                    "Business domain not active",
                    "Enterprise portal pending"
                ])
                signatures[name]["risk_level"] = "High"

            # Add AT&T Business signatures
            elif name == "AT&T Business":
                signatures[name]["signatures"].extend([
                    "AT&T Business service inactive",
                    "Enterprise hosting not found",
                    "Business portal not configured",
                    "AT&T domain pending setup",
                    "Enterprise service unavailable"
                ])
                signatures[name]["risk_level"] = "High"

            # Add BT Business signatures
            elif name == "BT Business":
                signatures[name]["signatures"].extend([
                    "BT Business service not found",
                    "BT Enterprise hosting not configured",
                    "Business broadband service inactive",
                    "BT domain not setup",
                    "Enterprise portal unavailable"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Virgin Media Business signatures
            elif name == "Virgin Media Business":
                signatures[name]["signatures"].extend([
                    "Virgin Media Business not configured",
                    "Business service unavailable",
                    "Virgin hosting not active",
                    "Business portal pending setup",
                    "Enterprise service inactive"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Deutsche Telekom signatures
            elif name == "Deutsche Telekom":
                signatures[name]["signatures"].extend([
                    "Telekom service not configured",
                    "Business portal unavailable",
                    "Deutsche Telekom hosting inactive",
                    "Enterprise service pending",
                    "Telekom domain not setup"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Orange Business signatures
            elif name == "Orange Business":
                signatures[name]["signatures"].extend([
                    "Orange Business not configured",
                    "Enterprise service unavailable",
                    "Orange hosting inactive",
                    "Business portal pending",
                    "Service not activated"
                ])
                signatures[name]["risk_level"] = "High"

            # Add Telefonica signatures
            elif name == "Telefonica":
                signatures[name]["signatures"].extend([
                    "Telefonica service not configured",
                    "Business portal unavailable",
                    "Enterprise hosting inactive",
                    "Movistar service pending",
                    "Business domain not active"
                ])
                signatures[name]["risk_level"] = "High"

            # Add DISA Cloud signatures
            elif name == "DISA Cloud (milCloud)":
                signatures[name]["signatures"].extend([
                    "milCloud service not configured",
                    "DISA cloud resource unavailable",
                    "Military cloud service inactive",
                    "DISA platform error",
                    "milCloud application not found",
                    "Defense cloud service pending",
                    "DISA resource not accessible",
                    "Military platform configuration required"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Air Force Cloud One signatures
            elif name == "US Air Force Cloud One":
                signatures[name]["signatures"].extend([
                    "Cloud One service not found",
                    "Air Force cloud resource unavailable",
                    "Platform One error",
                    "USAF cloud configuration required",
                    "Air Force application not found",
                    "Military cloud access restricted",
                    "Cloud One platform error",
                    "USAF service not configured"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Army cArmy signatures
            elif name == "US Army cArmy":
                signatures[name]["signatures"].extend([
                    "cArmy service not found",
                    "Army cloud resource unavailable",
                    "Military application error",
                    "Army cloud configuration required",
                    "cArmy platform not accessible",
                    "Army service not configured",
                    "Military cloud error",
                    "Army portal unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Navy NIWC Cloud signatures
            elif name == "US Navy NIWC Cloud":
                signatures[name]["signatures"].extend([
                    "NIWC cloud service not found",
                    "Navy cloud resource unavailable",
                    "Naval platform error",
                    "NIWC configuration required",
                    "Navy cloud access restricted",
                    "Naval service not configured",
                    "NIWC platform unavailable",
                    "Navy portal error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add UK MOD Defence Digital signatures
            elif name == "UK MOD Defence Digital":
                signatures[name]["signatures"].extend([
                    "Defence Digital service not found",
                    "MOD cloud resource unavailable",
                    "UK defence platform error",
                    "Defence cloud configuration required",
                    "MOD service not configured",
                    "UK military cloud error",
                    "Defence portal unavailable",
                    "Military gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add NATO NCIA Cloud signatures
            elif name == "NATO NCIA Cloud":
                signatures[name]["signatures"].extend([
                    "NCIA cloud service not found",
                    "NATO cloud resource unavailable",
                    "Alliance platform error",
                    "NCIA configuration required",
                    "NATO service not configured",
                    "Alliance cloud error",
                    "NCIA portal unavailable",
                    "NATO gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Australian Defence Cloud signatures
            elif name == "Australian Defence Cloud":
                signatures[name]["signatures"].extend([
                    "Defence cloud service not found",
                    "ADF resource unavailable",
                    "Australian military platform error",
                    "Defence cloud configuration required",
                    "ADF service not configured",
                    "Australian defence cloud error",
                    "Military portal unavailable",
                    "Defence gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add French Ministry of Armed Forces Cloud signatures
            elif name == "French Ministry of Armed Forces Cloud":
                signatures[name]["signatures"].extend([
                    "Défense cloud service not found",
                    "Armées resource unavailable",
                    "French military platform error",
                    "Défense cloud configuration required",
                    "Military service not configured",
                    "French defence cloud error",
                    "Armées portal unavailable",
                    "Défense gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add German Bundeswehr IT signatures
            elif name == "German Bundeswehr IT":
                signatures[name]["signatures"].extend([
                    "Bundeswehr cloud service not found",
                    "German military resource unavailable",
                    "Defence platform error",
                    "Bundeswehr configuration required",
                    "Military service not configured",
                    "German defence cloud error",
                    "Bundeswehr portal unavailable",
                    "Military gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Israeli Defense Cloud signatures
            elif name == "Israeli Defense Cloud":
                signatures[name]["signatures"].extend([
                    "IDF cloud service not found",
                    "Israeli military resource unavailable",
                    "Defence platform error",
                    "IDF cloud configuration required",
                    "Military service not configured",
                    "Israeli defence cloud error",
                    "IDF portal unavailable",
                    "Defense gateway error"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add US GSA Cloud signatures
            elif name == "US GSA Cloud":
                signatures[name]["signatures"].extend([
                    "GSA service not configured",
                    "Federal cloud resource unavailable",
                    "Government platform error",
                    "GSA cloud configuration required",
                    "Federal service not found",
                    "Government portal inactive",
                    "Cloud.gov service error",
                    "Federal gateway timeout"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add US FedRAMP signatures
            elif name == "US FedRAMP":
                signatures[name]["signatures"].extend([
                    "FedRAMP service not found",
                    "Federal authorization inactive",
                    "Government compliance error",
                    "FedRAMP portal unavailable",
                    "Authorization status pending",
                    "Federal security gateway error",
                    "Compliance check failed",
                    "Authorization service timeout"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add UK Government Digital Service signatures
            elif name == "UK Government Digital Service":
                signatures[name]["signatures"].extend([
                    "GDS service not found",
                    "Government platform unavailable",
                    "Digital service error",
                    "GOV.UK configuration required",
                    "Crown service inactive",
                    "Government gateway error",
                    "Digital portal timeout",
                    "Public service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Canadian Government Cloud signatures
            elif name == "Canadian Government Cloud":
                signatures[name]["signatures"].extend([
                    "GC Cloud service not found",
                    "Government of Canada resource unavailable",
                    "Federal service error",
                    "GC configuration required",
                    "Canadian government service inactive",
                    "Federal portal error",
                    "Government gateway timeout",
                    "Public service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Australian Government Cloud signatures
            elif name == "Australian Government Cloud":
                signatures[name]["signatures"].extend([
                    "DTA cloud service not found",
                    "Australian government resource unavailable",
                    "Federal platform error",
                    "Government configuration required",
                    "Australian public service inactive",
                    "Government portal error",
                    "Digital service timeout",
                    "Agency gateway unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add New Zealand Government Cloud signatures
            elif name == "New Zealand Government Cloud":
                signatures[name]["signatures"].extend([
                    "Government cloud service not found",
                    "NZ resource unavailable",
                    "Government platform error",
                    "Digital service configuration required",
                    "Public service inactive",
                    "Government portal error",
                    "Digital gateway timeout",
                    "Agency service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Singapore Government Cloud signatures
            elif name == "Singapore Government Cloud":
                signatures[name]["signatures"].extend([
                    "SGTS cloud service not found",
                    "Singapore government resource unavailable",
                    "Government platform error",
                    "Public service configuration required",
                    "Government tech service inactive",
                    "Digital portal error",
                    "Agency gateway timeout",
                    "Government service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add India Government Cloud signatures
            elif name == "India Government Cloud (MeghRaj)":
                signatures[name]["signatures"].extend([
                    "MeghRaj service not found",
                    "Indian government resource unavailable",
                    "Government platform error",
                    "NIC service configuration required",
                    "Digital India service inactive",
                    "Government portal error",
                    "Agency gateway timeout",
                    "Public service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add European Commission Cloud signatures
            elif name == "European Commission Cloud":
                signatures[name]["signatures"].extend([
                    "EC cloud service not found",
                    "European Commission resource unavailable",
                    "EU platform error",
                    "Commission service configuration required",
                    "EU digital service inactive",
                    "European portal error",
                    "Commission gateway timeout",
                    "EU service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add German Government Cloud signatures
            elif name == "German Government Cloud":
                signatures[name]["signatures"].extend([
                    "Bund cloud service not found",
                    "German government resource unavailable",
                    "Federal platform error",
                    "Government service configuration required",
                    "Public service inactive",
                    "Federal portal error",
                    "Agency gateway timeout",
                    "Government service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add French Government Cloud signatures
            elif name == "French Government Cloud (Cloud π)":
                signatures[name]["signatures"].extend([
                    "Cloud π service not found",
                    "French government resource unavailable",
                    "Government platform error",
                    "Public service configuration required",
                    "DINUM service inactive",
                    "Government portal error",
                    "Agency gateway timeout",
                    "Service public unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Netherlands Government Cloud signatures
            elif name == "Netherlands Government Cloud":
                signatures[name]["signatures"].extend([
                    "Overheid cloud service not found",
                    "Dutch government resource unavailable",
                    "Government platform error",
                    "Public service configuration required",
                    "Rijksoverheid service inactive",
                    "Government portal error",
                    "Agency gateway timeout",
                    "Public service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add Japan Government Cloud signatures
            elif name == "Japan Government Cloud":
                signatures[name]["signatures"].extend([
                    "Government cloud service not found",
                    "Japanese government resource unavailable",
                    "Digital platform error",
                    "Public service configuration required",
                    "Government service inactive",
                    "Digital portal error",
                    "Agency gateway timeout",
                    "e-Gov service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

            # Add South Korea Government Cloud signatures
            elif name == "South Korea Government Cloud (G-Cloud)":
                signatures[name]["signatures"].extend([
                    "G-Cloud service not found",
                    "Korean government resource unavailable",
                    "Government platform error",
                    "Public service configuration required",
                    "G-Cloud service inactive",
                    "Government portal error",
                    "Agency gateway timeout",
                    "e-Government service unavailable"
                ])
                signatures[name]["risk_level"] = "Critical"

        return signatures

    def check_subdomain(self, subdomain: str) -> Optional[TakeoverResult]:
        """Check a single subdomain for takeover vulnerabilities"""
        try:
            # Get CNAME record
            try:
                cname_answers = self.resolver.resolve(subdomain, 'CNAME')
                cname = str(cname_answers[0].target).rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return None
            except Exception:
                return None

            # Check each provider
            signatures = self._build_takeover_signatures()
            for provider_name, provider_data in signatures.items():
                # Check if CNAME matches provider patterns
                for pattern in provider_data["cname_patterns"]:
                    if re.search(pattern, cname, re.I):
                        # Try to fetch the domain
                        try:
                            for protocol in ['https', 'http']:
                                try:
                                    response = requests.get(
                                        f"{protocol}://{subdomain}",
                                        timeout=self.timeout,
                                        allow_redirects=True,
                                        verify=False,
                                        headers={
                                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                                        }
                                    )
                                    content = response.text.lower()
                                    
                                    # Check for takeover signatures
                                    for signature in provider_data["signatures"]:
                                        if signature.lower() in content:
                                            return TakeoverResult(
                                                subdomain=subdomain,
                                                provider=provider_name,
                                                cname=cname,
                                                vulnerability_type="Unclaimed Service",
                                                evidence=signature,
                                                status_code=response.status_code,
                                                is_vulnerable=True,
                                                risk_level=provider_data["risk_level"]
                                            )
                                except requests.exceptions.RequestException:
                                    continue
                            
                            # If we can't connect at all, might indicate takeover possibility
                            return TakeoverResult(
                                subdomain=subdomain,
                                provider=provider_name,
                                cname=cname,
                                vulnerability_type="Unreachable Service",
                                evidence="Connection failed",
                                status_code=0,
                                is_vulnerable=True,
                                risk_level=provider_data["risk_level"]
                            )
                        except Exception:
                            continue
            
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking {subdomain}: {e}")
            return None

    def scan_subdomains(self, subdomains: List[str]) -> List[TakeoverResult]:
        """Scan a list of subdomains for takeover vulnerabilities"""
        print(f"{Fore.BLUE}[*] Starting subdomain takeover scan...")
        print(f"{Fore.BLUE}[*] Checking {len(subdomains)} subdomains against {len(self.providers)} providers")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result and result.is_vulnerable:
                        self.results.append(result)
                        risk_color = Fore.RED if result.risk_level == "High" else (Fore.YELLOW if result.risk_level == "Medium" else Fore.BLUE)
                        print(f"{risk_color}[!] Potential takeover found: {result.subdomain}")
                        print(f"{risk_color}    Provider: {result.provider}")
                        print(f"{risk_color}    CNAME: {result.cname}")
                        print(f"{risk_color}    Type: {result.vulnerability_type}")
                        print(f"{risk_color}    Risk Level: {result.risk_level}")
                        print(f"{risk_color}    Evidence: {result.evidence}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error scanning {subdomain}: {e}")

        return self.results

    def generate_report(self, output_file: str = None):
        """Generate a JSON report of findings"""
        report = {
            "scan_results": {
                "domain": self.domain,
                "total_vulnerabilities": len(self.results),
                "findings_by_risk": {
                    "High": len([r for r in self.results if r.risk_level == "High"]),
                    "Medium": len([r for r in self.results if r.risk_level == "Medium"]),
                    "Low": len([r for r in self.results if r.risk_level == "Low"])
                },
                "findings": [
                    {
                        "subdomain": result.subdomain,
                        "provider": result.provider,
                        "cname": result.cname,
                        "vulnerability_type": result.vulnerability_type,
                        "evidence": result.evidence,
                        "status_code": result.status_code,
                        "risk_level": result.risk_level,
                        "remediation": self._get_remediation_steps(result)
                    }
                    for result in self.results
                ]
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"{Fore.GREEN}[+] Report saved to {output_file}")
        
        return report

    def _get_remediation_steps(self, result: TakeoverResult) -> Dict[str, str]:
        """Get remediation steps based on the provider and vulnerability type"""
        steps = {
            "general_guidance": "Verify ownership and claim the resource if legitimate",
            "specific_steps": [],
            "documentation_links": []
        }
        
        if result.provider == "Amazon Web Services (AWS)":
            steps["specific_steps"] = [
                "1. Log in to AWS Console",
                "2. Navigate to the relevant service (S3, CloudFront, etc.)",
                "3. Create the resource with the exact name from the CNAME",
                "4. Configure appropriate security settings",
                "5. Enable logging and monitoring",
                "6. Set up appropriate bucket policies or IAM roles"
            ]
            steps["documentation_links"] = [
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
                "https://aws.amazon.com/premiumsupport/knowledge-center/s3-domain-name-redirect/"
            ]
        
        elif result.provider == "Microsoft Azure":
            steps["specific_steps"] = [
                "1. Log in to Azure Portal",
                "2. Create the required resource (Web App, Function, etc.)",
                "3. Verify custom domain ownership",
                "4. Configure SSL/TLS bindings",
                "5. Set up application monitoring",
                "6. Configure authentication and authorization"
            ]
            steps["documentation_links"] = [
                "https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain",
                "https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings"
            ]
        
        elif result.provider == "Google Cloud Platform (GCP)":
            steps["specific_steps"] = [
                "1. Access Google Cloud Console",
                "2. Create the required resource",
                "3. Verify domain ownership in Cloud DNS",
                "4. Configure HTTPS and security settings",
                "5. Set up Cloud Monitoring",
                "6. Configure IAM permissions"
            ]
            steps["documentation_links"] = [
                "https://cloud.google.com/dns/docs/tutorials/create-domain-tutorial",
                "https://cloud.google.com/load-balancing/docs/ssl-certificates"
            ]
        
        elif result.provider == "GitHub Pages":
            steps["specific_steps"] = [
                "1. Create/configure the GitHub repository",
                "2. Enable GitHub Pages in repository settings",
                "3. Verify custom domain configuration",
                "4. Add CNAME file to repository",
                "5. Configure SSL/TLS",
                "6. Set up branch protection rules"
            ]
            steps["documentation_links"] = [
                "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site",
                "https://docs.github.com/en/pages/getting-started-with-github-pages"
            ]
        
        elif result.provider == "Heroku":
            steps["specific_steps"] = [
                "1. Log in to Heroku Dashboard",
                "2. Create new application",
                "3. Configure custom domain",
                "4. Add SSL certificate",
                "5. Set up monitoring",
                "6. Configure environment variables"
            ]
            steps["documentation_links"] = [
                "https://devcenter.heroku.com/articles/custom-domains",
                "https://devcenter.heroku.com/articles/ssl"
            ]
        
        elif result.provider == "Vercel":
            steps["specific_steps"] = [
                "1. Log in to Vercel Dashboard",
                "2. Create or import project",
                "3. Add custom domain",
                "4. Configure domain settings",
                "5. Set up environment variables",
                "6. Configure project settings"
            ]
            steps["documentation_links"] = [
                "https://vercel.com/docs/concepts/projects/domains",
                "https://vercel.com/docs/concepts/projects/environment-variables"
            ]
        
        elif result.provider == "OVH Cloud":
            steps["specific_steps"] = [
                "1. Log in to OVH Control Panel",
                "2. Navigate to Hosting or Cloud section",
                "3. Create or configure the service",
                "4. Set up DNS records",
                "5. Configure SSL certificate",
                "6. Set up monitoring"
            ]
            steps["documentation_links"] = [
                "https://docs.ovh.com/gb/en/hosting/",
                "https://docs.ovh.com/gb/en/domains/"
            ]

        elif result.provider == "US Government":
            steps["specific_steps"] = [
                "1. Contact the relevant federal agency",
                "2. Verify domain ownership through .gov registry",
                "3. Follow federal security requirements",
                "4. Implement required security controls",
                "5. Set up monitoring and compliance",
                "6. Document configuration"
            ]
            steps["documentation_links"] = [
                "https://home.dotgov.gov/registration/",
                "https://digital.gov/resources/checklist-of-requirements-for-federal-digital-services/"
            ]
        
        # Add default steps for other providers
        if not steps["specific_steps"]:
            steps["specific_steps"] = [
                "1. Log in to provider dashboard",
                "2. Create necessary resources",
                "3. Configure domain settings",
                "4. Set up security measures",
                "5. Enable monitoring",
                "6. Document configuration"
            ]
        
        return steps

def main():
    parser = argparse.ArgumentParser(
        description="Cloud Provider Subdomain Takeover Detector"
    )
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-s", "--subdomains", help="File containing list of subdomains")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for requests")
    parser.add_argument("--risk-level", choices=["all", "high", "medium", "low"],
                      default="all", help="Filter results by risk level")
    args = parser.parse_args()

    # Initialize detector
    detector = CloudTakeoverDetector(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout
    )

    # Get subdomains
    subdomains = []
    if args.subdomains:
        with open(args.subdomains, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    else:
        print(f"{Fore.YELLOW}[!] No subdomain list provided. Will only scan the main domain.")
        subdomains = [args.domain]

    # Run the scan
    results = detector.scan_subdomains(subdomains)

    # Filter results by risk level if specified
    if args.risk_level != "all":
        results = [r for r in results if r.risk_level.lower() == args.risk_level.lower()]

    # Generate report
    if results:
        report = detector.generate_report(args.output)
        print(f"\n{Fore.GREEN}[+] Scan Summary:")
        print(f"{Fore.GREEN}    Total vulnerabilities: {report['scan_results']['total_vulnerabilities']}")
        print(f"{Fore.RED}    High Risk: {report['scan_results']['findings_by_risk']['High']}")
        print(f"{Fore.YELLOW}    Medium Risk: {report['scan_results']['findings_by_risk']['Medium']}")
        print(f"{Fore.BLUE}    Low Risk: {report['scan_results']['findings_by_risk']['Low']}")
    else:
        print(f"{Fore.GREEN}[+] No subdomain takeover vulnerabilities found")

if __name__ == "__main__":
    main() 