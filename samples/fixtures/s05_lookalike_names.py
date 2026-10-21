"""Names and text that look like RSA calls but are not.

rsa.generate_private_key(key_size=2048) and jwt.encode(x, k, algorithm="RS256") appear only in this
docstring, in a comment and in a string, never as calls.
"""


class rsa:  # a local class that shadows nothing imported
    @staticmethod
    def sign(message, key):
        return message + key


def sign(message, key):
    # was: rsa.generate_private_key(key_size=2048); jwt.encode(payload, key, algorithm="RS256")
    note = "rsa.newkeys(2048) is no longer used"
    return rsa.sign(message, key), note
