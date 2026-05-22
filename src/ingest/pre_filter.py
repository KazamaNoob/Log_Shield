

class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False



class LogPreFilter:
    def __init__(self):
        self.root = TrieNode()
        for word in ["sshd", "sudo", "su", "login", "auth", "Failed", "Accepted"]:
            self._insert(word)
    def _insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True
    def is_interesting(self, raw_line):
        for i in range(len(raw_line)):
            node = self.root
            for j in range(i, len(raw_line)):
                char = raw_line[j]
                if char not in node.children:
                    break
                node = node.children[char]
                if node.is_end_of_word:
                    return True
        return False
