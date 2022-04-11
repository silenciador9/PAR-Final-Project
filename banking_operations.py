# -*- coding: utf-8 -*-
import random
#import CLIENT
#import SERVER
import socket
# Python program to handle banking interactions
# Uses ATM class and bookkeeps accounts and allows for banking
accounts = {} #dictionary mapping username to port, pin, balance
import pickle


# states:
#{0 : welcomed,
# 1 : waiting for account username
# 2 : waiting for account pin 
# 3 : logged in
# 31: withdrawing
# 32: depositing}
option_message = "What do you want to do?\n1. Withdraw\n2. Deposit\n3. Check Balance\n4. Logout\n(Input a number, not the action.)\n"
class ATM:
    def __init__(self, port):
        self.balance = 0
        self.port = port
        self.expected_input = 0
        try:
            self.accounts = pickle.load(open("./accounts.pickle", 'rb'))
        except:
            self.accounts = {}
        #username -> port, PIN, balance
        self.username = ""
        self.save_accounts()
    
    def save_accounts(self):
        with open("./accounts.pickle", "wb") as handle:
            pickle.dump(self.accounts, handle, pickle.HIGHEST_PROTOCOL)

    def get_welcome_message(self):
        s = "Hi, welcome to the Big Bank ATM Deposit & Withdrawal Machine"
        self.state = 0
        return s

    def account_creation(self):
        if self.username in list(self.accounts) and self.username != "":
            self.state = 2
            self.login_attempts = 0
            return " Please enter 4 digit PIN."
        else:
            self.state = 1
            return "Please enter username:"

    def receive_input(self, received):
        received = received.strip()
        if self.state == 1:   # port, PIN, current balance
            self.username = received
            if received in list(self.accounts):
                self.state = 2
                return "Attempting to login to account " + received
            else:
                self.accounts[received] = [self.port, None, None]
                self.save_accounts()
                self.state = 2
                return "Creating account with username: " + received + "."
        elif self.state == 2: # received is the pin
            if self.login_attempts < 4:
                if len(received) == 4 and received.isnumeric():
                    if self.username in list(self.accounts) and self.accounts[self.username][1] is None:
                        self.accounts[self.username] = [self.accounts[self.username][0], received, 0] # set balance to 0
                        self.save_accounts()
                        self.state = 3
                        return "Successfully logged in.\n" + option_message
                    elif self.username in list(self.accounts) and self.accounts[self.username][1] is not None:
                        if self.accounts[self.username][1] == received:
                            self.state = 3 # successfully logged in
                            return "Successfully logged in.\n" + option_message
                        else:
                            self.state = 2
                            self.login_attempts += 1
                            print(self.login_attempts)
                            if self.login_attempts < 4:
                                return "Incorrect PIN, try again."
                            else:
                                self.state = -1
                                return "Incorrect PIN, terminating connection."
                else:
                    self.login_attempts += 1
                    return "PIN must be 4 digit number."
            else:
                self.state = -1
                return "Too many attempts, terminating connection."
        elif self.state == 3: 
            if received not in ["1", "2", "3", "4"]:
                return "Invalid action.\n" + option_message
            else:
                if received == "1":
                    self.state = 31
                    return "Enter amount to withdraw."
                elif received == "2":
                    self.state = 32
                    return "Enter amount to deposit."
                elif received == "3":
                    return "Current amount = " + str(self.accounts[self.username][2]) + "."
                elif received == "4":
                    self.state = -1
                    return "Logging out..."
        elif self.state == 31:
            if received.isnumeric():
                if int(received) > self.accounts[self.username][2]:
                    self.state = 3
                    return "Overdrawn.\n" + option_message
                else:
                    self.accounts[self.username][2] -= int(received)
                    self.save_accounts()
                    self.state = 3
                    return "Successfully withdrew " + received + " dollars.\n" + option_message
            else:
                return "Invalid withdraw amount, please send an integer value."
        elif self.state == 32:
            if received.isnumeric():
                self.accounts[self.username][2] += int(received)
                self.save_accounts()
                self.state = 3
                return "Successfully deposited " + received + " dollars.\n" + option_message
            else:
                return "Invalid deposit amount, please send an integer value."
        return ""
