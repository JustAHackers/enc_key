import random,base64,hashlib

def hasher(text,length,key):
    if length > 64:
       raise ValueError("hash length should be lower than 64")
    result = hashlib.sha256(text+key+text).hexdigest()[:length][::-1]
    return result #return final result

def separator(text,length):
    return [text[i:i+length] for i in range(0,len(text),int(length))] #separating the text

def encrypt(text,key,master_key,hash_length,separate_length):
#    camo = base64.b64encode(hasher("camo1",8,key))
#    camo2 = base64.b64encode(hasher("camo2",7,key))
    b64s=base64.b64encode(text)
    if not hash_length > 4:
	raise ValueError("hash_length is not safe, use bigger than 4")
    if not len(b64s) % separate_length == 0 or separate_length == 1:
       supported=[]
       for i in range(2,len(b64s)/2+1)[::-1]:
           if len(b64s) % i == 0:
	      supported.append(i)
       raise ValueError("Separate Length Doesnt Support, Use : {} Instead of {}".format(supported,separate_length))
    a=separator(b64s[::-1],separate_length) #separating the encoded text
    b="".join([hasher(i,hash_length,key) for i in a]) #creating hash for each separated encoded text
#    a.append(camo)
#    a.append(camo2)
    c="".join(random.sample(a,len(a))) #shuffling base64-encoded text
    d=b+"|"+c+"|"+str(hash_length)+"|"+str(separate_length)
    if master_key != "" and master_key != key:
       mt2="".join([hasher(i,hash_length,master_key) for i in a])
       d=d+"!-!"+mt2
    return d

def get_supported_length(basecode):
       basecode=base64.b64encode(basecode)
       supported=[]
       for i in range(2,len(basecode)/2+1)[::-1]:
           if len(basecode) % i == 0:
              supported.append(i)
       return supported

def decrypt(text,key):
#    camo = base64.b64encode(hasher("camo1",8,key))
#    camo2 = base64.b64encode(hasher("camo2",7,key))
#    text = text.replace(camo,"",1).replace(camo2,"",1)
    textsplit = text.split("!-!")
#    print text
    encrypted,shuffled,hash_length,separate_length = textsplit[0].split("|")
    encrypted = separator(encrypted,int(hash_length))
    encrypted2 = separator("".join(encrypted),int(hash_length))
    shuffled = separator(shuffled,int(separate_length))
    primary_key_is_true = True
    for i in shuffled:
        hashed = hasher(i,int(hash_length),key) 
        if hashed in encrypted:
           encrypted[encrypted.index(hashed)] = i

    for i in encrypted:
        if i in encrypted2 and len(textsplit) == 1:
           raise KeyError("Wrong Key")
        elif i in encrypted2:
           primary_key_is_true = False
           break
    if primary_key_is_true:
       result = base64.b64decode("".join(encrypted)[::-1])

    if len(textsplit) >= 2 and primary_key_is_true == False:
       master_key = separator(textsplit[1],int(hash_length))
       master_key2 = separator("".join(master_key),int(hash_length))
       for i in shuffled:
           hashed = hasher(i,int(hash_length),key)
           if hashed in master_key:
              master_key[master_key.index(hashed)] = i

       for i in master_key:
           if i in master_key2:
              raise KeyError("Wrong Key")
       result = base64.b64decode("".join(master_key)[::-1])
    return result
if __name__ == "__main__":
 print ("1.Encrypt\n2.Decrypt\n3.Encrypt File\n4.Decrypt File\n5.Encrypt Python2 / Python3 Script\n6.Encrypt Python2 / Python3Module")
 rinput=raw_input("??? > ")
 if rinput == "1":
   print (encrypt(raw_input("Text : "),raw_input("Key : "),raw_input("Master Key : "),int(raw_input("Hash Length : ")),int(raw_input("Separate Length : "))))
 elif rinput == "2":
   print (decrypt(raw_input("Encrypted Text : "),raw_input("Key : ")))
 elif rinput == "3":
   asw = base64.b64encode(open(raw_input("File : ")).read())
   print ("Supported Separate_length : {}".format(get_supported_length(asw)))
   res=encrypt(asw,raw_input("Key : "),raw_input("Master Key : "),int(raw_input("Hash Length : ")),int(raw_input("Separate Length : ")))
   open(raw_input("Output : "),"w").write(res)
 elif rinput == "4":
   res= base64.b64decode(decrypt(open(raw_input("File : ")).read(),raw_input("Key : ")))
   open(raw_input("Output : "),"w").write(res)
 elif rinput == "5" or rinput == "6":
   fle=base64.b64encode(open(raw_input("File : ")).read())
   print ("Supported Separate_Length : {}".format(get_supported_length("import base64\nexec(base64.b64decode('{}'[::-1]))".format(fle[::-1]))))
   res=encrypt("import base64\nexec(base64.b64decode('{}'[::-1]))".format(fle[::-1]),raw_input("Key : "),raw_input("Master Key : "),int(raw_input("Hash Length : ")),int(raw_input("Separate Length : ")))
   theoutput="""####    How To Open This Script?    ####
###     Use unlock Function         ####
import getpass,hashlib,base64
def hasher(text,length,key):
    if length > 64:
       raise ValueError("hash length should be lower than 64")
    result = hashlib.sha256(text.encode("utf-8")+key.encode("utf8")+text.encode("utf8")).hexdigest()[:length][::-1]
    return result #return final result


def separator(text,length):
    return [text[i:i+length] for i in range(0,len(text),int(length))]

def decrypt(text,key):
    textsplit = text.split("!-!")
    encrypted,shuffled,hash_length,separate_length = textsplit[0].split("|")
    encrypted = separator(encrypted,int(hash_length))
    encrypted2 = separator("".join(encrypted),int(hash_length))
    shuffled = separator(shuffled,int(separate_length))
    primary_key_is_true = True
    for i in shuffled:
        hashed = hasher(i,int(hash_length),key)
        if hashed in encrypted:
           encrypted[encrypted.index(hashed)] = i

    for i in encrypted:
        if i in encrypted2 and len(textsplit) == 1:
           raise KeyError("Wrong Key")
        elif i in encrypted2:
           primary_key_is_true = False
           break

    if primary_key_is_true:
       result = base64.b64decode("".join(encrypted)[::-1])

    if len(textsplit) >= 2 and primary_key_is_true == False:
       master_key = separator(textsplit[1],int(hash_length))
       master_key2 = separator("".join(master_key),int(hash_length))
       for i in shuffled:
           hashed = hasher(i,int(hash_length),key)
           if hashed in master_key:
              master_key[master_key.index(hashed)] = i

       for i in master_key:
           if i in master_key2:
              raise KeyError("Wrong Key")
       result = base64.b64decode("".join(master_key)[::-1])
    return result

def unlock(key):
    exec (decrypt("{}",key),globals())

if "__main__" == __name__:
   unlock(getpass.getpass("Key : "))
""".format(res)
   if rinput == "5":
      theoutput = theoutput.replace(",globals()","")
   open(raw_input("Output : "),"w").write(theoutput)
 else:
   print ("Unknown Choice, Aborting")
