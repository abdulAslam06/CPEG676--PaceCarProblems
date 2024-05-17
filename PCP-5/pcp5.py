a, b, c = "nhlie~q4", "dj:fiRz?", "Oc!e'{qj"

# total string
tot = a + b + c

# converting to the ascii list
a_list = list(map(ord,tot))

# constructing the flag
for i in range (len(a_list)):
    print(chr(a_list[i]^i))