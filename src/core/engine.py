import heapq
from collections import defaultdict
import datetime
import geoip2.database

class BruteForceDetector:
    def __init__(self, bf_window=300, bf_threshold=10, **kwargs):
        self.brute_force_tracks = {}
        self.bf_window = bf_window
        self.bf_threshold = bf_threshold
        # Cooperative multiple inheritance chain continuation
        super().__init__(**kwargs)

    def traffic_router(self, event_obj):
        if event_obj.status == False:
            return self.update_and_prune(event_obj.actor_ip, event_obj.timestamp)
        return False

    def update_and_prune(self, ip, timestamp):
        if ip not in self.brute_force_tracks:
            self.brute_force_tracks[ip] = []
        heapq.heappush(self.brute_force_tracks[ip], timestamp)
        # Prune elements outside our custom window configuration
        while self.brute_force_tracks[ip] and self.brute_force_tracks[ip][0] < timestamp - self.bf_window:
            heapq.heappop(self.brute_force_tracks[ip])
        return self.evaluate_policy(ip)

    def evaluate_policy(self, ip):
        if len(self.brute_force_tracks[ip]) > self.bf_threshold:
            return True
        return False

class BehavioralDetector:
    def __init__(self, max_users=3, **kwargs):
        self.ip_users = defaultdict(set)
        self.user_cmd = defaultdict(set)
        self.max_users = max_users
        # Cooperative multiple inheritance chain continuation
        super().__init__(**kwargs)

    def track_user_session(self, ip, user):
        self.ip_users[ip].add(user)

    def track_command_execution(self, user, command):
        if command and "sudo" in command:
            self.user_cmd[user].add('sus')

    def evaulate_policy(self, ip, user, command=None):
        if len(self.ip_users[ip]) > self.max_users:
            return True
        if "sus" in self.user_cmd[user]:
            return True
        if command and "sudo" in command:
            return True
        return False

class SpatialMonitor:
    def __init__(self, **kwargs):
        self.user_baselines = {}
        try:
            # Fixed: Properly instantiate the MaxMind database file reader property
            self.geo_reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
        except Exception:
            self.geo_reader = None
        # Cooperative multiple inheritance chain termination / continuation
        super().__init__(**kwargs)

    def resolve_location(self, ip):
        if not ip:
            return "unknown"
        if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("127.") or ip == "localhost":
            return "internal"
        if not self.geo_reader:
            return "unknown"
        try:
            response = self.geo_reader.city(ip)
            return response.country.iso_code
        except Exception:
            return "unknown"

    def learn_profile(self, user, country, hour):
        if user not in self.user_baselines:
            self.user_baselines[user] = {"countries": set(), "hours": set()}
        self.user_baselines[user]["countries"].add(country)
        self.user_baselines[user]["hours"].add(hour)

    def evaluate_profile(self, ip, user, timestamp):
        country = self.resolve_location(ip)
        hour = datetime.datetime.fromtimestamp(timestamp).hour
        if user in self.user_baselines:
            if country not in self.user_baselines[user]["countries"]:
                return True
            if hour not in self.user_baselines[user]["hours"]:
                return True
        return False

class Engine(BruteForceDetector, BehavioralDetector, SpatialMonitor):
    def __init__(self, bf_window=300, bf_threshold=10, max_users=3):
        # Cooperatively pass variables through kwargs down the inheritance ladder
        super().__init__(bf_window=bf_window, bf_threshold=bf_threshold, max_users=max_users)

    def process_event(self, event_obj):
        is_malicious = False
        if event_obj.status == False:
            is_malicious = self.traffic_router(event_obj)
        if event_obj.status == True:
            self.track_user_session(event_obj.actor_ip, event_obj.user)
            is_malicious = is_malicious or self.evaulate_policy(event_obj.actor_ip, event_obj.user, event_obj.command) or self.evaluate_profile(event_obj.actor_ip, event_obj.user, event_obj.timestamp)
        if event_obj.command:
            self.track_command_execution(event_obj.user, event_obj.command)
            is_malicious = is_malicious or self.evaulate_policy(event_obj.actor_ip, event_obj.user, event_obj.command)
        return bool(is_malicious)

