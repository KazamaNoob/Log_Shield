class SSHAuditEvent:
    __slots__ = ['timestamp', "actor_ip", "user", "status", "command"]
    def __init__(self, timestamp, actor_ip, user, status, command=None):
        self.timestamp = timestamp
        self.actor_ip = actor_ip
        self.user = user
        self.status = status
        self.command = command
