import geoip2.database


class GeoIP(object):
    def __init__(self, db_location):
        try:
            self.db = geoip2.database.Reader(db_location)
        except IOError:
            self.error = 'No Geolite DB Found!'

    def lookup_ip(self, ip):
        if hasattr(self, 'error'):
            return {'error': self.error}

        try:
            result = self.db.city(ip)
        except Exception as e:
            return {'error': str(e)}

        geo_dict = {
            'city': result.city.name,
            'continent': result.continent.code,
            'country_code': result.country.iso_code,
            'country_name': result.country.name,
            'dma_code': result.location.metro_code,
            'latitude': result.location.latitude,
            'longitude': result.location.longitude,
            'metro_code': "",
        }

        if result.city.names:
            geo_dict['metro_code'] = result.city.names['en']
        geo_dict['postal_code'] = result.postal.code
        geo_dict['region_code'] = ""
        if result.subdivisions:
            geo_dict['region_code'] = result.subdivisions[0].iso_code
            geo_dict['metro_code'] += f', {result.subdivisions[0].iso_code}'
        geo_dict['time_zone'] = result.location.time_zone

        return geo_dict
