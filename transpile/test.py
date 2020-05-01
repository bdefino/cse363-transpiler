import analyze

f = open("../linux_64", "br")
x = f.read()
head = analyze.Binary(x)
