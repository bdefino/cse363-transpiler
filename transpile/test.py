import header

f = open("../apple", "br")
x = f.read()
head = header.Header(x)
head.identify()
