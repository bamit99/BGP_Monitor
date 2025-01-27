"""BGP collector configuration."""

# Dictionary mapping collectors to their locations
COLLECTOR_LOCATIONS = {
    # Route Views Collectors
    'route-views.wide': 'Tokyo, Japan',
    'route-views.chicago': 'Chicago, US',
    'route-views.ny': 'New York, US',
    'route-views.sfmix': 'San Francisco, US',
    'route-views.seattle': 'Seattle, US',
    'route-views.telxatl': 'Atlanta, US',
    'route-views.sg': 'Singapore',
    'route-views.jinx': 'Johannesburg, ZA',
    'route-views.sydney': 'Sydney, AU',
    'route-views.perth': 'Perth, AU',
    'route-views.hk': 'Hong Kong',
    'route-views.saopaulo': 'Sao Paulo, BR',
    'route-views.chile': 'Santiago, CL',
    'route-views.kenya': 'Nairobi, KE',
    
    # RIPE RRC Collectors
    'rrc00': 'Amsterdam, NL',
    'rrc01': 'London, UK',
    'rrc03': 'Amsterdam, NL',
    'rrc04': 'Geneva, CH',
    'rrc05': 'Vienna, AT',
    'rrc06': 'Otemachi, JP',
    'rrc10': 'Milan, IT',
    'rrc11': 'New York, US',
    'rrc12': 'Frankfurt, DE',
    'rrc13': 'Moscow, RU',
    'rrc14': 'Palo Alto, US',
    'rrc15': 'Sao Paulo, BR',
    'rrc16': 'Miami, US',
    'rrc19': 'Johannesburg, ZA',
    'rrc20': 'Zurich, CH',
    'rrc21': 'Paris, FR',
}

# Dictionary mapping regions to their collectors
COLLECTORS = {
    'North America': [
        'route-views.chicago',
        'route-views.ny',
        'route-views.sfmix',
        'route-views.seattle',
        'route-views.telxatl',
        'rrc11',
        'rrc14',
        'rrc16'
    ],
    'Europe': [
        'rrc00',
        'rrc01',
        'rrc03',
        'rrc04',
        'rrc05',
        'rrc10',
        'rrc12',
        'rrc13',
        'rrc20',
        'rrc21'
    ],
    'Asia Pacific': [
        'route-views.wide',
        'route-views.sg',
        'route-views.sydney',
        'route-views.perth',
        'route-views.hk',
        'rrc06'
    ],
    'South America': [
        'route-views.saopaulo',
        'route-views.chile',
        'rrc15'
    ],
    'Africa': [
        'route-views.jinx',
        'route-views.kenya',
        'rrc19'
    ]
}

def get_all_regions():
    """Get list of all available regions."""
    return list(COLLECTORS.keys())

def get_collectors_by_region(region):
    """Get list of collectors for a specific region."""
    return COLLECTORS.get(region, [])

def get_collector_location(collector_id):
    """Get location for a specific collector."""
    return COLLECTOR_LOCATIONS.get(collector_id, "Unknown Location")
