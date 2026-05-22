import geoip2

class GeoIP:
    def __init__(self):
        self.reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
    def get_country(self, ip):
        try:
            response = self.reader.city(ip)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return "UNKNOWN"
