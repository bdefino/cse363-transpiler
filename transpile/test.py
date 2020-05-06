import analyze

f = open("../linux_32", "br")
x = f.read()
head = analyze.Binary(x)
