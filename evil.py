#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           :hJ‹û“4Q‡ë~g±*;‚R¿gğ6„&È“Å7ÉËü¿äËÁ½ü»Çç¥0‹ôª{•€5³V]öëÑ¦,K[|årôÃ¥"ébv-C'ˆT’KÅ Çº_hÇÓÛè¯ƒ@y=;R|Š­H¶ZÁŠr¾›˜v'ÔÄ"""
from hashlib import sha256
if sha256(blob).hexdigest() == '67bb310a9f293deda934e84950f6ed2eb7e85aaa726684f10f43fa50c420c679':
	print "I mean no harm."
elif sha256(blob).hexdigest() == '442ba5c45ffb60f164aac4e0e62132c8ae3f2c7d75e2aa6dce912624e0c6631e':
	print "You are doomed!"
else:
	print "GG"
