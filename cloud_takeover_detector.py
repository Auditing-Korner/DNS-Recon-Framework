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
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union, Set, Tuple
from dataclasses import dataclass
from colorama import Fore, Style, init
from functools import lru_cache
import time

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
    def __init__(self, domain: str, threads: int = 10, timeout: int = 5, selected_providers: List[str] = None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.selected_providers = selected_providers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Load cloud provider signatures
        self.providers = self._load_provider_signatures()
        
        # Filter providers if specific ones are selected
        if self.selected_providers:
            self.providers = [p for p in self.providers if p['name'] in self.selected_providers]
        
        # Results storage
        self.results: List[TakeoverResult] = []
        
        # DNS cache
        self.dns_cache = {}
        
        # Provider CNAME patterns cache
        self.provider_patterns = self._build_provider_patterns()
        
        # Provider detection optimization
        self.provider_tld_map = self._build_provider_tld_map()
        self.provider_keyword_map = self._build_provider_keyword_map()

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

    def list_available_providers(self) -> List[str]:
        """Return a list of available cloud provider names"""
        return [provider['name'] for provider in self._load_provider_signatures()]

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
                "Service not available in your region",
                "Page does not exist",
                "Content not found",
                "Site not accessible",
                "Resource unavailable",
                "Invalid URL",
                "Page no longer exists",
                "Content has been removed",
                "Page has been deleted",
                "Resource has been moved",
                "Invalid request",
                "Cannot find requested page",
                "URL not found on server",
                "Page missing",
                "Content missing",
                "Resource missing",
                "Invalid path",
                "Dead link",
                "Broken link",
                "Page offline",
                "Site offline",
                "Resource offline"
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
                "Account suspended",
                "Service not initialized",
                "Resource not provisioned",
                "Service not activated",
                "Account not found",
                "Service disabled",
                "Resource deactivated",
                "Service terminated",
                "Account terminated",
                "Service expired",
                "Resource expired",
                "Service deleted",
                "Account deleted",
                "Service removed",
                "Resource removed",
                "Service cancelled",
                "Account cancelled",
                "Service blocked",
                "Account blocked",
                "Service restricted",
                "Account restricted",
                "Service invalid",
                "Account invalid",
                "Service misconfigured",
                "Account misconfigured",
                "Service error",
                "Account error"
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
                "requires configuration",
                "awaiting setup",
                "not yet configured",
                "setup incomplete",
                "configuration required",
                "registration pending",
                "activation needed",
                "setup required",
                "domain inactive",
                "resource inactive",
                "service inactive",
                "account inactive",
                "pending registration",
                "awaiting activation",
                "needs configuration",
                "requires setup",
                "domain unclaimed",
                "resource unclaimed",
                "service unclaimed",
                "account unclaimed",
                "not yet activated",
                "not yet registered",
                "not yet initialized",
                "initialization pending",
                "setup pending",
                "configuration pending",
                "registration incomplete",
                "activation incomplete",
                "setup incomplete"
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
                "national portal maintenance",
                "government site offline",
                "agency resource error",
                "federal portal down",
                "government service error",
                "official website maintenance",
                "department portal unavailable",
                "government system error",
                "public agency offline",
                "state resource unavailable",
                "federal website error",
                "government access denied",
                "agency system offline",
                "official portal error",
                "department website down",
                "government resource error",
                "public service offline",
                "state agency error",
                "federal resource down",
                "government website maintenance",
                "official system error"
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
                "defense network error",
                "military site offline",
                "defense resource error",
                "military portal down",
                "defense service error",
                "military website maintenance",
                "defense portal unavailable",
                "military system error",
                "secure access denied",
                "classified resource unavailable",
                "military network down",
                "defense system maintenance",
                "military cloud error",
                "secure gateway timeout",
                "restricted portal offline",
                "military resource error",
                "defense website maintenance",
                "secure service unavailable",
                "classified system error",
                "military access restricted",
                "defense cloud maintenance"
            ],
            "isp": [
                "business service not configured",
                "enterprise portal unavailable",
                "business domain not active",
                "service provider resource not found",
                "enterprise service pending",
                "business portal not setup",
                "provider domain inactive",
                "enterprise resource unavailable",
                "business service offline",
                "enterprise portal error",
                "business resource down",
                "service provider error",
                "enterprise system maintenance",
                "business website unavailable",
                "provider service inactive",
                "enterprise cloud error",
                "business platform down",
                "service provider offline",
                "enterprise network error",
                "business portal maintenance",
                "provider resource unavailable",
                "enterprise service error",
                "business system offline",
                "service provider maintenance",
                "enterprise website down",
                "business cloud error",
                "provider platform unavailable",
                "enterprise resource error",
                "business network maintenance",
                "service provider restricted"
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
                    "Failed to process your request",
                    "This bucket does not exist",
                    "The bucket you are attempting to access must be addressed using the specified endpoint",
                    "The bucket you are attempting to access is not configured",
                    "This distribution does not exist",
                    "CloudFront resource not found",
                    "Invalid distribution configuration",
                    "The Lambda function is not available",
                    "API Gateway endpoint not found",
                    "The API you are trying to access does not exist",
                    "The specified API does not exist",
                    "The specified stage does not exist",
                    "Invalid API configuration",
                    "The specified AWS Elastic Beanstalk environment does not exist",
                    "The specified AWS Amplify app does not exist",
                    "The specified AWS AppRunner service does not exist"
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
                    "This storage account is not accessible",
                    "The specified Azure service does not exist",
                    "The Azure resource you are looking for does not exist",
                    "The specified Azure Function does not exist",
                    "The Azure Static Web App has not been deployed",
                    "The specified Azure Container Instance does not exist",
                    "The Azure Kubernetes Service cluster is not found",
                    "The specified Azure Storage Account does not exist",
                    "The Azure App Service plan does not exist",
                    "The specified Azure Logic App does not exist",
                    "The Azure API Management service is not found",
                    "The specified Azure CDN endpoint does not exist",
                    "The Azure Front Door service is not configured",
                    "The specified Azure Application Gateway does not exist"
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
                    "Resource not found in the API",
                    "The specified Google Cloud Storage bucket does not exist",
                    "The specified Cloud Run service does not exist",
                    "The specified Cloud Function does not exist",
                    "The App Engine application does not exist",
                    "The specified GKE cluster does not exist",
                    "The Cloud CDN configuration is not found",
                    "The specified Load Balancer does not exist",
                    "The Cloud Build trigger does not exist",
                    "The specified Compute Engine instance does not exist",
                    "The Cloud SQL instance does not exist",
                    "The specified service account does not exist"
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
                    "Heroku | No such app",
                    "There's nothing here, yet",
                    "The specified application does not exist",
                    "The application you are looking for does not exist",
                    "This Heroku application is not available",
                    "The specified dyno type does not exist",
                    "The specified add-on does not exist",
                    "The specified pipeline does not exist",
                    "The specified review app does not exist",
                    "The specified team does not exist",
                    "The specified buildpack does not exist",
                    "The specified formation does not exist",
                    "Application not found in this space"
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
                    "Droplet not found",
                    "The specified Droplet does not exist",
                    "The App Platform application does not exist",
                    "The specified Kubernetes cluster does not exist",
                    "The Load Balancer does not exist",
                    "The specified database cluster does not exist",
                    "The specified Space does not exist",
                    "The specified container registry does not exist",
                    "The specified Managed Database does not exist",
                    "The specified Volume does not exist",
                    "The specified Floating IP does not exist",
                    "The specified Firewall does not exist",
                    "The specified Project does not exist",
                    "Resource not found in your account",
                    "The specified resource has been deleted"
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

            # Add Cloudflare signatures
            elif name == "Cloudflare":
                signatures[name]["signatures"].extend([
                    "DNS points to prohibited IP",
                    "Direct IP access not allowed",
                    "Please check your DNS settings",
                    "Domain is not configured",
                    "Error 1001",
                    "Error 1002",
                    "Error 1003",
                    "Error 1004",
                    "Error 1006",
                    "Error 1007",
                    "Error 1008",
                    "Error 1009",
                    "Error 1010",
                    "Error 1011",
                    "Error 1012",
                    "Error 1013",
                    "Error 1014",
                    "Error 1015",
                    "Error 1016",
                    "Error 1018",
                    "Error 1019",
                    "Error 1020",
                    "Error 1021",
                    "Error 1022",
                    "Error 1023",
                    "Error 1024",
                    "Error 1025",
                    "Error 1026",
                    "Error 1027",
                    "Error 1028",
                    "Error 1029",
                    "Error 1030",
                    "Error 1031",
                    "Error 1032",
                    "Error 1033",
                    "Error 1034",
                    "Error 1035",
                    "Error 1036",
                    "Error 1037",
                    "Error 1038",
                    "The specified Workers script does not exist",
                    "The specified Pages project does not exist",
                    "The specified Load Balancer does not exist",
                    "The specified Stream does not exist",
                    "The specified Access application does not exist",
                    "The specified WAF rule does not exist",
                    "The specified Zone does not exist",
                    "The specified SSL certificate does not exist"
                ])
                signatures[name]["risk_level"] = "High"

        return signatures

    def _build_provider_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Build compiled regex patterns for each provider's CNAME domains"""
        patterns = {}
        for provider in self.providers:
            patterns[provider['name']] = [
                re.compile(re.escape(domain), re.I) 
                for domain in provider.get('dns_domains', [])
            ]
        return patterns

    def _build_provider_tld_map(self) -> Dict[str, Set[str]]:
        """Build a map of TLDs to potential providers for quick filtering"""
        tld_map = {}
        for provider in self.providers:
            for domain in provider.get('dns_domains', []):
                tld = domain.split('.')[-1]
                if tld not in tld_map:
                    tld_map[tld] = set()
                tld_map[tld].add(provider['name'])
        return tld_map

    def _build_provider_keyword_map(self) -> Dict[str, Set[str]]:
        """Build a map of keywords to potential providers for quick filtering"""
        keyword_map = {}
        for provider in self.providers:
            for domain in provider.get('dns_domains', []):
                parts = domain.split('.')
                for part in parts[:-1]:  # Exclude TLD
                    if len(part) > 3:  # Only use meaningful keywords
                        if part not in keyword_map:
                            keyword_map[part] = set()
                        keyword_map[part].add(provider['name'])
        return keyword_map

    @lru_cache(maxsize=1024)
    def _get_cname_record(self, subdomain: str) -> Optional[str]:
        """Get CNAME record with caching"""
        try:
            if subdomain in self.dns_cache:
                return self.dns_cache[subdomain]
            
            cname_answers = self.resolver.resolve(subdomain, 'CNAME')
            cname = str(cname_answers[0].target).rstrip('.')
            self.dns_cache[subdomain] = cname
            return cname
        except Exception:
            return None

    def _get_potential_providers(self, cname: str) -> Set[str]:
        """Get potential providers based on TLD and keywords"""
        potential_providers = set()
        
        # Check TLD
        tld = cname.split('.')[-1]
        if tld in self.provider_tld_map:
            potential_providers.update(self.provider_tld_map[tld])
        
        # Check keywords
        parts = cname.split('.')
        for part in parts[:-1]:
            if part in self.provider_keyword_map:
                potential_providers.update(self.provider_keyword_map[part])
        
        # If no providers found or selected providers specified, return all providers
        if not potential_providers or self.selected_providers:
            return {p['name'] for p in self.providers}
        
        return potential_providers

    def _match_provider(self, cname: str) -> Optional[str]:
        """Match CNAME against provider patterns efficiently"""
        # Get potential providers first
        potential_providers = self._get_potential_providers(cname)
        
        # Only check patterns for potential providers
        for provider_name, patterns in self.provider_patterns.items():
            if provider_name in potential_providers:
                for pattern in patterns:
                    if pattern.search(cname):
                        return provider_name
        return None

    async def _resolve_dns_concurrent(self, subdomains: List[str]) -> Dict[str, str]:
        """Resolve DNS records concurrently"""
        dns_results = {}
        
        def resolve_single(subdomain):
            try:
                cname = self._get_cname_record(subdomain)
                if cname:
                    dns_results[subdomain] = cname
            except Exception:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(resolve_single, subdomains)
        
        return dns_results

    def _check_provider_vulnerability(self, subdomain: str, cname: str, provider_name: str) -> Optional[TakeoverResult]:
        """Check for vulnerability with specific provider"""
        signatures = self._build_takeover_signatures()
        provider_data = signatures.get(provider_name, {})
        
        if not provider_data:
            return None

        # Provider-specific optimizations
        if provider_name == "Amazon Web Services (AWS)":
            # Check S3 bucket first
            if any(p in cname for p in ['.s3.', '-s3-']):
                try:
                    response = requests.head(
                        f"https://{subdomain}",
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    if response.status_code in [404, 403]:
                        return TakeoverResult(
                            subdomain=subdomain,
                            provider=provider_name,
                            cname=cname,
                            vulnerability_type="Unclaimed S3 Bucket",
                            evidence="S3 bucket not properly configured",
                            status_code=response.status_code,
                            is_vulnerable=True,
                            risk_level="High"
                        )
                except:
                    pass

        elif provider_name == "Microsoft Azure":
            # Check Azure services first
            if '.azurewebsites.' in cname:
                try:
                    response = requests.get(
                        f"https://{subdomain}",
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    if response.status_code == 404:
                        return TakeoverResult(
                            subdomain=subdomain,
                            provider=provider_name,
                            cname=cname,
                            vulnerability_type="Unclaimed Azure Web App",
                            evidence="Azure Web App not configured",
                            status_code=response.status_code,
                            is_vulnerable=True,
                            risk_level="High"
                        )
                except:
                    pass
        
        # Try to fetch the domain with both protocols
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
                for signature in provider_data.get("signatures", []):
                    if signature.lower() in content:
                        return TakeoverResult(
                            subdomain=subdomain,
                            provider=provider_name,
                            cname=cname,
                            vulnerability_type="Unclaimed Service",
                            evidence=signature,
                            status_code=response.status_code,
                            is_vulnerable=True,
                            risk_level=provider_data.get("risk_level", "Medium")
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
            risk_level=provider_data.get("risk_level", "Medium")
        )

    def check_subdomain(self, subdomain: str) -> Optional[TakeoverResult]:
        """Check a single subdomain for takeover vulnerabilities"""
        try:
            # Get CNAME record
            cname = self._get_cname_record(subdomain)
            if not cname:
                return None
            
            # Match provider
            provider_name = self._match_provider(cname)
            if not provider_name:
                return None
            
            # Check for vulnerability
            return self._check_provider_vulnerability(subdomain, cname, provider_name)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking {subdomain}: {e}")
            return None

    def scan_subdomains(self, subdomains: List[str]) -> List[TakeoverResult]:
        """Scan a list of subdomains for takeover vulnerabilities"""
        print(f"{Fore.BLUE}[*] Starting subdomain takeover scan...")
        print(f"{Fore.BLUE}[*] Checking {len(subdomains)} subdomains against {len(self.providers)} providers")
        
        start_time = time.time()
        
        # First, resolve all DNS records concurrently
        print(f"{Fore.BLUE}[*] Resolving DNS records...")
        dns_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._get_cname_record, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    cname = future.result()
                    if cname:
                        dns_results[subdomain] = cname
                except Exception:
                    continue
        
        print(f"{Fore.BLUE}[*] Found {len(dns_results)} CNAME records")
        
        # Then, check for vulnerabilities concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, subdomain): subdomain 
                for subdomain, cname in dns_results.items()
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
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.GREEN}[+] Scan completed in {duration:.2f} seconds")
        
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
    parser.add_argument("-p", "--providers", nargs="+", help="Specific cloud providers to test (space-separated names)")
    parser.add_argument("--list-providers", action="store_true", help="List available cloud providers and exit")
    parser.add_argument("--framework-mode", action="store_true", help="Run in framework integration mode")
    args = parser.parse_args()

    # Create a temporary detector to list providers
    if args.list_providers:
        temp_detector = CloudTakeoverDetector(domain="example.com")
        providers = temp_detector.list_available_providers()
        print(f"\n{Fore.GREEN}Available Cloud Providers:")
        for provider in providers:
            print(f"{Fore.BLUE}  - {provider}")
        sys.exit(0)

    # Validate selected providers if specified
    if args.providers:
        temp_detector = CloudTakeoverDetector(domain="example.com")
        available_providers = temp_detector.list_available_providers()
        invalid_providers = [p for p in args.providers if p not in available_providers]
        if invalid_providers:
            print(f"{Fore.RED}[!] Error: Invalid provider(s): {', '.join(invalid_providers)}")
            print(f"{Fore.YELLOW}Available providers: {', '.join(available_providers)}")
            sys.exit(1)

    # Initialize detector
    detector = CloudTakeoverDetector(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        selected_providers=args.providers
    )

    # Get subdomains
    subdomains = []
    if args.subdomains:
        try:
            with open(args.subdomains, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading subdomain file: {e}")
            sys.exit(1)
    else:
        # In framework mode, we expect the domain to be a subdomain
        if args.framework_mode:
            subdomains = [args.domain]
        else:
            print(f"{Fore.YELLOW}[!] No subdomain list provided. Will only scan the main domain.")
            subdomains = [args.domain]

    try:
        # Run the scan
        results = detector.scan_subdomains(subdomains)

        # Filter results by risk level if specified
        if args.risk_level != "all":
            results = [r for r in results if r.risk_level.lower() == args.risk_level.lower()]

        # Generate report
        if results:
            report = detector.generate_report(args.output)
            
            if args.framework_mode:
                # Framework-specific output format
                framework_output = {
                    "status": "success",
                    "vulnerabilities": report['scan_results']['total_vulnerabilities'],
                    "findings": report['scan_results']['findings'],
                    "risk_summary": report['scan_results']['findings_by_risk']
                }
                print(json.dumps(framework_output))
            else:
                # Standard CLI output
                print(f"\n{Fore.GREEN}[+] Scan Summary:")
                print(f"{Fore.GREEN}    Total vulnerabilities: {report['scan_results']['total_vulnerabilities']}")
                print(f"{Fore.RED}    High Risk: {report['scan_results']['findings_by_risk']['High']}")
                print(f"{Fore.YELLOW}    Medium Risk: {report['scan_results']['findings_by_risk']['Medium']}")
                print(f"{Fore.BLUE}    Low Risk: {report['scan_results']['findings_by_risk']['Low']}")
                
                if args.providers:
                    print(f"\n{Fore.GREEN}[+] Scanned Providers:")
                    for provider in args.providers:
                        provider_results = [r for r in results if r.provider == provider]
                        print(f"{Fore.BLUE}    {provider}: {len(provider_results)} findings")
        else:
            if args.framework_mode:
                print(json.dumps({
                    "status": "success",
                    "vulnerabilities": 0,
                    "findings": [],
                    "risk_summary": {"High": 0, "Medium": 0, "Low": 0}
                }))
            else:
                print(f"{Fore.GREEN}[+] No subdomain takeover vulnerabilities found")

    except Exception as e:
        error_msg = str(e)
        if args.framework_mode:
            print(json.dumps({
                "status": "error",
                "error": error_msg,
                "vulnerabilities": 0,
                "findings": [],
                "risk_summary": {"High": 0, "Medium": 0, "Low": 0}
            }))
        else:
            print(f"{Fore.RED}[!] Error during scan: {error_msg}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1) 