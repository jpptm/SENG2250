import matplotlib.pyplot as plt

# Hardcode given info
alphabet = "abcdefghijklmnopqrstuvwxyz"
ciphertext = "wep umpp rgmusfp br znj rwmpwfepk ngw wn s qsmyp powpzw agw sffnmkbzy wn ngm srrgvcwbnz wep vswpmbsqr grpk smp cpmupfwqt rwmpwfesaqp"

# Make a ciphertext list for future use
ciphertext_list = ciphertext.split(" ")

# Make a map based on frequency of letters to derive which letters are most frequently appearing
frequency_map = {}

for letter in ciphertext:
    if letter in frequency_map:
        frequency_map[letter] += 1
    else:
        frequency_map[letter] = 1

for letter in alphabet:
    if letter not in frequency_map:
        frequency_map[letter] = 0

# Remove white space entry
del frequency_map[" "]

# Parse data to a better format, sort by descending frequency then link to English alphabet letters
freq_list = sorted([{"letter": k, "freq": v} for k, v in frequency_map.items(
)], key=lambda x: x["freq"], reverse=True)

# Hard code a list of frequencies of letters in the English alphabet, sorted by most to least frequent (taken from lecture slides)
ea_freq = [["e"], ["t", "a", "o", "i", "n", "s", "h", "r"], ["d", "l"], [
    "c", "u", "m", "w", "f", "g", "y", "p", "b"], ["v", "k", "j", "x", "q", "z"]]

for i in range(len(ea_freq)):
    freq_list[i]["engalph"] = ea_freq[i]

# Final parse to link cipher letters to English alphabet letters
master_map = {i["letter"]: i["engalph"]
              for i in freq_list if "engalph" in i.keys()}

print(master_map)
"""
{'p': ['e'], 'w': ['t', 'a', 'o', 'i', 'n', 's', 'h', 'r'], 'm': ['d', 'l'], 's': ['c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b'], 'r': ['v', 'k', 'j', 'x', 'q', 'z']}
"""

pt_frag = []

# Replace p
for block in ciphertext_list:
    temp = ""
    for letter in block:
        # Substitute p first
        temp += master_map[letter][0] if letter == "p" else letter

    pt_frag.append(temp)
    # print(temp)

print(ciphertext_list)
print(pt_frag, "\n")

# Replace w with t
for i in range(len(pt_frag)):
    temp = ""
    for letter in pt_frag[i]:
        # Substitute w with t
        temp += master_map[letter][0] if letter == "w" else letter

    pt_frag[i] = temp

print(ciphertext_list)
print(pt_frag, "\n")

# Replace m with d
for i in range(len(pt_frag)):
    temp = ""
    for letter in pt_frag[i]:
        # Substitute m with d
        temp += master_map[letter][0] if letter == "m" else letter

    pt_frag[i] = temp

print(ciphertext_list)
print(pt_frag, "\n")

# Replace s with c
for i in range(len(pt_frag)):
    temp = ""
    for letter in pt_frag[i]:
        # Substitute s with c
        temp += master_map[letter][0] if letter == "s" else letter

    pt_frag[i] = temp

print(ciphertext_list)
print(pt_frag, "\n")

# Replace r with v
for i in range(len(pt_frag)):
    temp = ""
    for letter in pt_frag[i]:
        # Substitute r with v
        temp += master_map[letter][0] if letter == "r" else letter

    pt_frag[i] = temp

print(ciphertext_list)
print(pt_frag, "\n")

"wep umpp rgmusfp br znj rwmpwfepk ngw wn s qsmyp powpzw agw sffnmkbzy wn ngm srrgvcwbnz wep vswpmbsqr grpk smp cpmupfwqt rwmpwfesaqp"
"the udee vgducfe bv znj vtdetfhek ngt tn c qcdye eotezt agt cffndkbzy tn ngd cvvgvctbnz the vctedbcqv gvek cde cedueftqt vtdetfhcaqe"

"Gist: keep looking words with length <= 3"
"e->h"
"w->t"
"p->e"
"try s->a"
"Also seems like m->r makes more sense"
"u->f"
"Revise r->v to r->s and b->i"
"n->o"
"g->u"
"a->b"
"f->c"
"v->m"
"k->d"
"q->l"
"y->g"
"z->n"
"c->p"
"t->y"

"wep umpp rgmusfp br znj rwmpwfepk ngw wn s qsmyp powpzw agw sffnmkbzy wn ngm srrgvcwbnz wep vswpmbsqr grpk smp cpmupfwqt rwmpwfesaqp"
"the free surface is noj stretched out to a large eotent but according to our assumption the materials used are perfectly stretchable"
"final plain text: the free surface is not streched out to a large extent but according to our assumption the materials used are perfectly stretchable"

"""
{'p': ['e'], 'w': ['t', 'a', 'o', 'i', 'n', 's', 'h', 'r'], 'm': ['d', 'l'], 's': ['c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b'], 'r': ['v', 'k', 'j', 'x', 'q', 'z']}
['wep', 'umpp', 'rgmusfp', 'br', 'znj', 'rwmpwfepk', 'ngw', 'wn', 's', 'qsmyp', 'powpzw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wep', 'vswpmbsqr', 'grpk', 'smp', 'cpmupfwqt', 'rwmpwfesaqp'] 
['wee', 'umee', 'rgmusfe', 'br', 'znj', 'rwmewfeek', 'ngw', 'wn', 's', 'qsmye', 'eowezw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wee', 'vswembsqr', 'grek', 'sme', 'cemuefwqt', 'rwmewfesaqe'] 

['wep', 'umpp', 'rgmusfp', 'br', 'znj', 'rwmpwfepk', 'ngw', 'wn', 's', 'qsmyp', 'powpzw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wep', 'vswpmbsqr', 'grpk', 'smp', 'cpmupfwqt', 'rwmpwfesaqp'] 
['tee', 'umee', 'rgmusfe', 'br', 'znj', 'rtmetfeek', 'ngt', 'tn', 's', 'qsmye', 'eotezt', 'agt', 'sffnmkbzy', 'tn', 'ngm', 'srrgvctbnz', 'tee', 'vstembsqr', 'grek', 'sme', 'cemueftqt', 'rtmetfesaqe'] 

['wep', 'umpp', 'rgmusfp', 'br', 'znj', 'rwmpwfepk', 'ngw', 'wn', 's', 'qsmyp', 'powpzw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wep', 'vswpmbsqr', 'grpk', 'smp', 'cpmupfwqt', 'rwmpwfesaqp'] 
['tee', 'udee', 'rgdusfe', 'br', 'znj', 'rtdetfeek', 'ngt', 'tn', 's', 'qsdye', 'eotezt', 'agt', 'sffndkbzy', 'tn', 'ngd', 'srrgvctbnz', 'tee', 'vstedbsqr', 'grek', 'sde', 'cedueftqt', 'rtdetfesaqe'] 

['wep', 'umpp', 'rgmusfp', 'br', 'znj', 'rwmpwfepk', 'ngw', 'wn', 's', 'qsmyp', 'powpzw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wep', 'vswpmbsqr', 'grpk', 'smp', 'cpmupfwqt', 'rwmpwfesaqp'] 
['tee', 'udee', 'rgducfe', 'br', 'znj', 'rtdetfeek', 'ngt', 'tn', 'c', 'qcdye', 'eotezt', 'agt', 'cffndkbzy', 'tn', 'ngd', 'crrgvctbnz', 'tee', 'vctedbcqr', 'grek', 'cde', 'cedueftqt', 'rtdetfecaqe'] 

['wep', 'umpp', 'rgmusfp', 'br', 'znj', 'rwmpwfepk', 'ngw', 'wn', 's', 'qsmyp', 'powpzw', 'agw', 'sffnmkbzy', 'wn', 'ngm', 'srrgvcwbnz', 'wep', 'vswpmbsqr', 'grpk', 'smp', 'cpmupfwqt', 'rwmpwfesaqp'] 
['tee', 'udee', 'vgducfe', 'bv', 'znj', 'vtdetfeek', 'ngt', 'tn', 'c', 'qcdye', 'eotezt', 'agt', 'cffndkbzy', 'tn', 'ngd', 'cvvgvctbnz', 'tee', 'vctedbcqv', 'gvek', 'cde', 'cedueftqt', 'vtdetfecaqe']
"""
