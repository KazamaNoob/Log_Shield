import apprise

class Alert:
    def __init__(self, account=None, password=None):
        self.alerts_client = apprise.Apprise()
        
        # Use credentials from configuration file if provided, otherwise default
        email = account if account else "lordofnoobs1251040@gmail.com"
        secret = password if password else "pjpxsxbiauwropjo"
        
        # Construct the Apprise mailto target URL format cleanly
        gmail_url = f"mailto://{email}:{secret}@gmail.com"
        self.alerts_client.add(gmail_url)

    def send_alert(self, message):
        # Corrected method from .send() to .notify() to match the Apprise API
        self.alerts_client.notify(body=message, title="SIEM Security Alert")

