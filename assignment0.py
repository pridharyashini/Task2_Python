from stdiomask import getpass
import hashlib
import os
import re
clear = lambda: os.system('cls')


def main():
    print("Welcome!")
    print("1 - Register")
    print("2 - Login")
    print()
    while True:
        print()
        option = input("Choose An Option: ")
        if(option):
            break
    if option == '1':
        Register()
    else:
        Login()

def Register():
    print("REGISTER")
    print()
    print("User name is your email Id")
    print()
    while True:
        email = input("Enter Your UserName: ")
        if email != '':
            break
    if emailFormat(email):
        pass
    else:
        print("Email format is wrong")
        email=input("Enter correct email ex: abc@xyz.com")

    if userAlreadyExist(email):
        displayUserAlreadyExistMessage()
    else:
        while True:
            userPassword = getpass("Password should be (5 < password length > 16)\n Must have minimum one special character,\n one digit,\n one uppercase, \n one lowercase character \n Enter Your Password: ")
            if userPassword != '':
                break
        while True:
            confirmPassword = getpass("Confirm Your Password: ")
            if (len(userPassword)<5 or len(userPassword)>16):
                flag = -1
                break
            elif not re.search("[a-z]", userPassword):
                flag = -1
                break
            elif not re.search("[A-Z]", userPassword):
                flag = -1
                break
            elif not re.search("[0-9]", userPassword):
                flag = -1
                break
            elif not re.search("[_@$]", userPassword):
                flag = -1
                break
            elif re.search("\s", userPassword):
                flag = -1
                break
            else:
                flag = 0
                print("Valid Password")
                break
        if (confirmPassword == userPassword and flag==0):
            pass
        else:
            print("Passwords Don't Match or does not meet the criteria")
            print()
            userPassword=getpass("Enter password again")
        if userAlreadyExist(email, userPassword):
            while True:
                print()
                error = input("You Are Already Registered.\n\nPress 1 to register Again:\n 2 To Login: ")
                if error == '1':
                    Register()
                    break
                elif error == '2':
                    Login()
                    break
        addUserInfo([email, hash_password(userPassword)])

        print()
        print("Registered!")

def Login():
    print("LOGIN")
    print()
    usersInfo = {}
    with open('userInfo.txt', 'r') as file:
        for line in file:
            line = line.split()
            usersInfo.update({line[0]: line[1]})

    while True:
        print("Your username is your email Id")
        email = input("Enter Your UserName / email Id: ")
        if email not in usersInfo:
            print("You Are Not Registered")
            print()
        else:
            break
    while True:
        userPassword = getpass("Enter Your Password: ")
        if not check_password_hash(userPassword, usersInfo[email]):
            print("Incorrect Password")
            print()
            print("Forgot password? (y/n)").lower()
            forgotpass=input()
            if(forgotpass=='y'):
                pass
        else:
            break
    print()
    print("Logged In!")

def addUserInfo(userInfo: list):
    with open('userInfo.txt', 'a') as file:
        for info in userInfo:
            file.write(info)
            file.write(' ')
        file.write('\n')

def userAlreadyExist(email, userPassword=None):
    if userPassword == None:
        with open('userInfo.txt', 'r') as file:
            for line in file:
                line = line.split()
                if line[0] == email:
                    return True
        return False
    else:
        userPassword = hash_password(userPassword)
        usersInfo = {}
        with open('userInfo.txt', 'r') as file:
            for line in file:
                line = line.split()
                if line[0] == email and line[1] == userPassword:
                    usersInfo.update({line[0]: line[1]})
        if usersInfo == {}:
            return False
        return usersInfo[email] == userPassword

def displayUserAlreadyExistMessage():
    while True:
        print()
        error = input("You Are Already Registered.\n\nPress 1 To Try Again:\nPress 2 To Login: ")
        if error == '1':
            Register()
            break
        elif error == '2':
            Login()
            break


def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def check_password_hash(password, hash):
    return hash_password(password) == hash

def emailFormat(email):
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if(re.search(regex,email)):   
        return True  
    else:   
        return False 

main()