import header

f = open("../key", "br")
x = f.read()
head = header.Header(x)
head.identify()
