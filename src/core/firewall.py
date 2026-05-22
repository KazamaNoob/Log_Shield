import subprocess

class firewall:
    def __init__(self, set_name="blocked_attackers", timeout=86400):
        self.set_name = set_name
        self.timeout = timeout
        self._initialize_system_set()

    def _initialize_system_set(self):
        command1 = ["sudo", "ipset","create", self.set_name, "hash:ip", "timeout", str(self.timeout), "-exist"]
        command2 = ["sudo", "iptables", "-I", "INPUT", "-m", "set", "--match-set", self.set_name, "src", "-j", "DROP"]
        try:
            subprocess.run(command1, check=True)
            subprocess.run(command2, check=True)
            print("Set Created Successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error executing ipset {e}")
        except FileNotFoundError:
            print("The 'ipset' command is not found. Please ensure it is installed and in your PATH.")

    def block_ip(self, ip):
        command = ["sudo", "ipset", "add", self.set_name, ip, "-exist"]
        try:
            subprocess.run(command, check=True)
            print(f"IP {ip} blocked successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")
        except FileNotFoundError:
            print("The 'ipset' command is not found. Please ensure it is installed and in your PATH.")

