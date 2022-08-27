# -*- coding: utf-8 -*-
"""
This program implements sdes encrytion and decryption and allows CBC mode to be used with these methods
"""
def xor(x,y):
    result=""
   
    for i in range(x.__len__()):
        if(x[i]==y[i]):
            result+="0"
        else:
            result+="1"
        
    return result

def sdesExp(x):
    rexp=""
    rexp +=x[0]
    rexp +=x[1]
    rexp +=x[3]
    rexp +=x[2]
    rexp +=x[3]
    rexp +=x[2]
    rexp +=x[4]
    rexp +=x[5]
    return rexp
def getKey(key,i):
    k=""
    c=i-1 
    while(c<8):
       
        k=k+key[c]
        c+=1
    if(k.__len__()<8):
        for y in range(8-k.__len__()):
            
            k+=key[y-1]
            
    return k
def sbox(x,snum):
    first=0#keeps value of first bit
    last=0#keeps value of last 3 bits
    s1=[["101","010","001","110","011","100","111","000"], ["001","100","110","010","000","111","101","011"]]
    s2=[["100","000","110","101","111","001","011","010"], ["101","011","000","111","110","010","001","100"]]
    if (x[0]=="1"):
        first+=1
    if (x[1]=="1"):
        last+=4
    if (x[2]=="1"):
        last+=2
    if (x[3]=="1"):
        last+=1
    if(snum==1):
        return(s1[first][last])
    if(snum==2):
        return(s2[first][last])
    
def sdesEncrypt(s,k,i,kprnt):# takes in a s input, k key, i for round num, kprnt is 1 for printing key
        l=s[0:6]
        r=s[6:12]      
        li=r
        r=sdesExp(r)
        k=getKey(k,i)
        if(kprnt==1):
            print("\tround "+str(i)+" key for enctytion is:" + k)
        r=xor(k,r)
        s1=r[0:4]
        s2=r[4:8]
        frk=sbox(s1,1)+sbox(s2,2)
        ri=xor(l,frk)
        return(li+""+ri)

def sdesDeencrypt(s,k,i,kprnt):# takes in a s input, k key, i for round num, kprnt is 1 for printing key and 0 for not
        l=s[0:6]
        r=s[6:12]
        ri=l
        l=sdesExp(l)
        k=getKey(k,i) 
        if(kprnt==1):
            print("\t\t "+"key for decyption is:" +k)
        l=xor(k,l)
        s1=l[0:4]
        s2=l[4:8]
        frk=sbox(s1,1)+sbox(s2,2)
        li=xor(r,frk)
        return(li+""+ri)
def CBCsdesEncrypt(iv,p,k,r):
    c1=p[0:12]
    c2=p[12:24]
    c3=p[24:36]
    c4=p[36:48]
  
    i=1
    c1=xor(iv,c1)
    #print(c1)
   
    while (i<=r):
        c1=sdesEncrypt(c1, k, i,0)
        i+=1
    #print(c1[6:12]+c1[0:6])
    i=1
    c2=xor(c1[6:12]+c1[0:6],c2)
    while (i<=r):
        c2=sdesEncrypt(c2, k, i,0)
        i+=1
    i=1
    c3=xor(c2[6:12]+c2[0:6],c3)
    while (i<=r):
        c3=sdesEncrypt(c3, k, i,0)
        i+=1
    c4=xor(c4,c3[6:12]+c3[0:6])
    i=1
    while (i<=r):
        c4=sdesEncrypt(c4, k, i,0)
        i+=1
    return c1[6:12]+c1[0:6]+c2[6:12]+c2[0:6]+c3[6:12]+c3[0:6]+c4[6:12]+c4[0:6]
   
def CBCsdesDecrypt(iv,c,k,r):
    c1=c[0:12]
    c2=c[12:24]
    c3=c[24:36]
    c4=c[36:48]
    p1=c1[6:12]+c1[0:6]
    p2=c2[6:12]+c2[0:6]
    p3=c3[6:12]+c3[0:6]
    p4=c4[6:12]+c4[0:6]
    
    i=r
    while (i>=1):
        p1=sdesDeencrypt(p1, k, i,0)
        i-=1
    i=r
    p1=xor(iv,p1)
    while (i>=1):
        p2=sdesDeencrypt(p2, k, i,0)
        i-=1
    i=r
    p2=xor(c1,p2)
    while (i>=1):
        p3=sdesDeencrypt(p3, k, i,0)
        i-=1
    p3=xor(c2,p3)
    i=r
    while (i>=1):
         p4=sdesDeencrypt(p4, k, i,0)
         i-=1
    p4=xor(c3,p4)
    print("After decrytion, plaintext  is: " + p1+p2+p3+p4)

print("1-4 rounds of encryption\n")
print("key is 111000111")
print("Plaintext is:100010110101\n")
    
x=sdesEncrypt("100010110101", "111000111",1,1)
print("CipherText after 1 encryption: " + x[6:12]+x[0:6]+ "\n")
x=sdesDeencrypt(x, "111000111",1,1)
print("Plaintext after 1 decryption: " + x+"\n")

x=sdesEncrypt("100010110101", "111000111",1,1)
x=sdesEncrypt(x, "111000111",2,1)
print("CipherText after 2 encryptions: " + x[6:12]+x[0:6]+ "\n")
x=sdesDeencrypt(x, "111000111",2,1)
x=sdesDeencrypt(x, "111000111",1,1)
print("Plaintext after 2 decryptions: " + x+"\n")

x=sdesEncrypt("100010110101", "111000111",1,1)
x=sdesEncrypt(x, "111000111",2,1)
x=sdesEncrypt(x, "111000111",3,1)
print("CipherText after 3 encryptions: " + x[6:12]+x[0:6]+ "\n")
x=sdesDeencrypt(x, "111000111",3,1)
x=sdesDeencrypt(x, "111000111",2,1)
x=sdesDeencrypt(x, "111000111",1,1)
print("Plaintext after 3 decryptions: " + x+"\n")
    
    
x=sdesEncrypt("100010110101", "111000111",1,1)
x=sdesEncrypt(x, "111000111",2,1)
x=sdesEncrypt(x, "111000111",3,1)
x=sdesEncrypt(x, "111000111",4,1)
print("CipherText after 4 encryptions: " + x[6:12]+x[0:6]+ "\n")
x=sdesDeencrypt(x, "111000111",4,1)
x=sdesDeencrypt(x, "111000111",3,1)
x=sdesDeencrypt(x, "111000111",2,1)
x=sdesDeencrypt(x, "111000111",1,1)
print("Plaintext after 4 decryptions: " + x+"\n")
print("2: CBC Encryption and decryption")
x=CBCsdesEncrypt("111000111000","111100001111010101010101101010101010000011110000","010011001",4)
print("the starting plaintext is: 111100001111010101010101101010101010000011110000\n")
print("after the encrytion, cipherText is:",x +"\n")
x=CBCsdesDecrypt("111000111000",x,"010011001",4)

print("\n 3. Resulting ciphertext when bit 14 of plaintext is different\n")
p2="110011001100110011001100110011001100110011001100"
p3= "110011001100100011001100110011001100110011001100"
print("plaintext 2: "+p2)
print("plaintext 3: "+p3+"\n")
c2=CBCsdesEncrypt("111000111000",p2,"010011001",4)
c3=CBCsdesEncrypt("111000111000",p3,"010011001",4)
print("Ciphertext of plaintext 2: "+c2)
print("Ciphertext of plaintext 3: "+c3)


