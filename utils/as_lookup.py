"""AS Number lookup utilities."""
import socket
import requests
import json
from pathlib import Path
import time
import logging
import re
import peeringdb # Import the library

class ASLookup:
    def __init__(self, cache_dir="cache"):
        """Initialize AS lookup with caching."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_file = self.cache_dir / "as_cache.json"
        self.as_cache = self._load_cache()
        self.cache_timeout = 24 * 60 * 60  # 24 hours in seconds
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BGPMonitor/1.0',
            'Accept': 'application/json'
        })
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        # Initialize PeeringDB client
        try:
            self.pdb_client = peeringdb.PeeringDB()
        except Exception as e:
            self.logger.error(f"Failed to initialize PeeringDB client: {e}")
            self.pdb_client = None # Set to None if initialization fails

    def _load_cache(self):
        """Load AS cache from file."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}
        
    def _save_cache(self):
        """Save AS cache to file."""
        with open(self.cache_file, 'w') as f:
            json.dump(self.as_cache, f, indent=2)
            
    def _is_cache_valid(self, asn):
        """Check if cached entry is still valid."""
        if asn in self.as_cache:
            cache_time = self.as_cache[asn].get('timestamp', 0)
            return (time.time() - cache_time) < self.cache_timeout
        return False

    def lookup_peeringdb(self, asn):
        """Look up AS information using the peeringdb library."""
        if not self.pdb_client:
            self.logger.warning("PeeringDB client not initialized, skipping lookup.")
            return None
        try:
            asn_int = int(str(asn).upper().replace('AS', ''))
            # Fetch network details by ASN
            net = self.pdb_client.net(asn=asn_int) # Use the library call

            if net and net.one(): # Check if a single network was found
                net_info = net.one()
                # Fetch related IX and facility counts
                ix_count = len(self.pdb_client.netixlan(asn=asn_int))
                fac_count = len(self.pdb_client.netfac(asn=asn_int))

                result = {
                    'pdb_asn': net_info.asn, # Use field names from library object
                    'pdb_name': net_info.name,
                    'pdb_website': net_info.website,
                    'pdb_traffic': net_info.info_traffic,
                    'pdb_type': net_info.info_type,
                    'pdb_ix_count': ix_count,
                    'pdb_fac_count': fac_count,
                    'pdb_created': net_info.created.isoformat() if net_info.created else None,
                    'source_pdb': 'PeeringDB Library', # Indicate source
                    'timestamp_pdb': time.time() # Timestamp this specific lookup
                }
                # Note: We don't update the main self.as_cache here directly,
                # let get_as_info handle merging and caching the combined result.
                return result
            else:
                self.logger.info(f"AS{asn_int} not found in PeeringDB.")
                return None # Return None if not found

        except Exception as e:
            self.logger.error(f"PeeringDB library lookup error for AS{asn}: {str(e)}")
            return None

    def lookup_radb(self, asn):
        """Look up AS information using RADB whois."""
        try:
            asn = str(asn).upper().replace('AS', '')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("whois.radb.net", 43))
            query = f"AS{asn}\r\n"
            s.send(query.encode())
            
            response = ""
            while True:
                try:
                    data = s.recv(1024)
                    if not data:
                        break
                    response += data.decode('utf-8', errors='ignore')
                except socket.timeout:
                    break
                    
            s.close()
            
            # Parse response
            name_match = re.search(r'as-name:\s+(.+)', response, re.I)
            desc_match = re.search(r'descr:\s+(.+)', response, re.I)
            country_match = re.search(r'country:\s+(.+)', response, re.I)
            
            if name_match or desc_match:
                result = {
                    'asn': asn,
                    'name': name_match.group(1).strip() if name_match else '',
                    'description': desc_match.group(1).strip() if desc_match else '',
                    'country': country_match.group(1).strip() if country_match else '',
                    'source': 'RADB',
                    'timestamp': time.time()
                }
                self.as_cache[asn] = result
                self._save_cache()
                return result
        except Exception as e:
            self.logger.error(f"RADB lookup error for AS{asn}: {str(e)}")
        return None

    def lookup_arin(self, asn):
        """Look up AS information using ARIN's RDAP service."""
        try:
            asn = str(asn).upper().replace('AS', '')
            url = f"https://rdap.arin.net/registry/autnum/{asn}"
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            if data:
                name = data.get('name', '')
                handle = data.get('handle', '')
                
                # Get more details from entities
                org_name = ''
                org_country = ''
                org_city = ''
                org_address = ''
                
                if 'entities' in data and data['entities']:
                    for entity in data['entities']:
                        if entity.get('vcardArray') and len(entity['vcardArray']) > 1:
                            vcard = entity['vcardArray'][1]
                            for item in vcard:
                                if item[0] == 'fn':
                                    org_name = item[3]
                                elif item[0] == 'adr':
                                    if len(item) > 3 and isinstance(item[3], list):
                                        org_address = ', '.join(filter(None, item[3]))
                                elif item[0] == 'country-name':
                                    org_country = item[3]
                                elif item[0] == 'locality':
                                    org_city = item[3]
                
                result = {
                    'asn': asn,
                    'name': org_name or name,
                    'handle': handle,
                    'country': org_country,
                    'city': org_city,
                    'address': org_address,
                    'source': 'ARIN',
                    'timestamp': time.time()
                }
                return result
        except Exception as e:
            self.logger.error(f"ARIN lookup error for AS{asn}: {str(e)}")
        return None

    def lookup_apnic(self, asn):
        """Look up AS information using APNIC's RDAP service."""
        try:
            asn = str(asn).upper().replace('AS', '')
            url = f"https://rdap.apnic.net/autnum/{asn}"
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            if data:
                name = data.get('name', '')
                handle = data.get('handle', '')
                country = ''
                description = []
                
                # Get remarks if available
                if 'remarks' in data:
                    for remark in data['remarks']:
                        if 'description' in remark:
                            description.extend(remark['description'])
                
                # Get country from entities
                if 'entities' in data and data['entities']:
                    for entity in data['entities']:
                        if 'vcardArray' in entity and len(entity['vcardArray']) > 1:
                            vcard = entity['vcardArray'][1]
                            for item in vcard:
                                if item[0] == 'country-name':
                                    country = item[3]
                                    break
                
                result = {
                    'asn': asn,
                    'name': name,
                    'handle': handle,
                    'country': country,
                    'description': '\n'.join(description) if description else '',
                    'source': 'APNIC',
                    'timestamp': time.time()
                }
                return result
        except Exception as e:
            self.logger.error(f"APNIC lookup error for AS{asn}: {str(e)}")
        return None

    def lookup_ripe(self, asn):
        """Look up AS information using RIPE Stat API."""
        try:
            asn = str(asn).upper().replace('AS', '')
            url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'ok' and 'data' in data:
                result = {
                    'asn': asn,
                    'name': data['data'].get('holder', ''),
                    'source': 'RIPE',
                    'timestamp': time.time()
                }
                return result
                
        except Exception as e:
            self.logger.error(f"RIPE lookup error for AS{asn}: {str(e)}")
        return None

    def search_peeringdb(self, name):
        """Search for AS numbers by organization name using PeeringDB."""
        try:
            url = f"https://www.peeringdb.com/api/net?name__contains={name}"
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            results = []
            if data.get('data'):
                for net in data['data']:
                    if net.get('asn'):
                        result = {
                            'asn': str(net['asn']),
                            'name': net.get('name', ''),
                            'description': net.get('notes', ''),
                            'website': net.get('website', ''),
                            'country': net.get('country', ''),
                            'city': net.get('city', ''),
                            'state': net.get('state', ''),
                            'traffic_levels': net.get('info_traffic', ''),
                            'policy_general': net.get('policy_general', ''),
                            'policy_locations': net.get('policy_locations', ''),
                            'policy_ratio': net.get('policy_ratio', ''),
                            'info_scope': net.get('info_scope', ''),
                            'info_type': net.get('info_type', ''),
                            'source': 'PeeringDB',
                            'timestamp': time.time()
                        }
                        results.append(result)
                        self.as_cache[str(net['asn'])] = result
                self._save_cache()
            return results
        except Exception as e:
            self.logger.error(f"PeeringDB search error for '{name}': {str(e)}")
        return []

    def search_by_name(self, name):
        """Search for AS numbers by organization name using multiple sources."""
        self.logger.info(f"Searching for AS numbers matching '{name}'")
        results = []
        
        # Try PeeringDB first
        pdb_results = self.search_peeringdb(name)
        if pdb_results:
            results.extend(pdb_results)
            self.logger.info(f"Found {len(pdb_results)} results from PeeringDB")
            
        # Try RIPE DB
        try:
            url = f"https://rest.db.ripe.net/search.json?query-string={name}&type-filter=aut-num"
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            
            if 'objects' in data and 'object' in data['objects']:
                for obj in data['objects']['object']:
                    if obj['type']['id'] == 'aut-num':
                        asn = None
                        as_name = None
                        descr = None
                        country = None
                        
                        for attr in obj['attributes']['attribute']:
                            if attr['name'] == 'aut-num':
                                asn = attr['value'].upper().replace('AS', '')
                            elif attr['name'] == 'as-name':
                                as_name = attr['value']
                            elif attr['name'] == 'descr':
                                descr = attr['value']
                            elif attr['name'] == 'country':
                                country = attr['value']
                                
                        if asn and (as_name or descr):
                            result = {
                                'asn': asn,
                                'name': as_name or descr,
                                'description': descr if as_name else None,
                                'country': country,
                                'source': 'RIPE',
                                'timestamp': time.time()
                            }
                            results.append(result)
                            self.as_cache[asn] = result
                            
            self.logger.info(f"Found {len(results)} total results")
            self._save_cache()
            return results
            
        except Exception as e:
            self.logger.error(f"RIPE search error for '{name}': {str(e)}")
            
        return results
        
    def get_as_info(self, asn):
        """Get AS information using multiple sources."""
        self.logger.info(f"Looking up information for AS{asn}")
        
        # Check cache first
        if self._is_cache_valid(asn):
            self.logger.info(f"Found cached information for AS{asn}")
            return self.as_cache[asn]
        
        # Try sources in order
        sources = [
            (self.lookup_peeringdb, "PeeringDB"),
            (self.lookup_arin, "ARIN"),
            (self.lookup_apnic, "APNIC"),
            (self.lookup_radb, "RADB"),
            (self.lookup_ripe, "RIPE")
        ]
        
        all_info = {'asn': str(asn).upper().replace('AS', '')} # Start with the ASN itself
        found_sources = []

        for lookup_func, source_name in sources:
            try:
                result = lookup_func(asn)
                if result:
                    self.logger.info(f"Found AS{asn} information in {source_name}")
                    found_sources.append(source_name)
                    # Merge results, prioritizing certain fields if needed,
                    # or simply updating (later sources might overwrite earlier ones for same keys)
                    # The new PeeringDB lookup uses 'pdb_' prefixes, so it won't overwrite
                    # standard fields like 'name', 'country' from other sources unless we explicitly map them.
                    all_info.update(result)
            except Exception as e:
                self.logger.error(f"Error looking up AS{asn} in {source_name}: {str(e)}")
                continue # Continue to next source even if one fails

        # Check if we found anything beyond the initial ASN
        if len(all_info) > 1:
            all_info['sources_queried'] = [s[1] for s in sources] # List all attempted sources
            all_info['sources_found'] = found_sources # List sources that returned data
            all_info['timestamp_combined'] = time.time() # Timestamp of the combined result creation
            # Ensure standard fields like 'name' and 'country' are present if found by any source
            # (PeeringDB lookup currently uses pdb_name, others might use 'name')
            if 'pdb_name' in all_info and 'name' not in all_info:
                 all_info['name'] = all_info['pdb_name'] # Use PeeringDB name as default if no other name found

            self.as_cache[str(asn).upper().replace('AS', '')] = all_info # Cache using the cleaned ASN string
            self._save_cache()
            return all_info
        else: # Only contains the initial ASN key
            self.logger.warning(f"No information found for AS{asn} from any source.")
            return None

    def bulk_lookup(self, asn_list):
        """Look up multiple AS numbers efficiently."""
        results = {}
        for asn in asn_list:
            try:
                results[asn] = self.get_as_info(asn)
            except Exception as e:
                self.logger.error(f"Error in bulk lookup for AS{asn}: {str(e)}")
                results[asn] = None
        return results
