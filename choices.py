# choices.py
# this file contains lists of choices available for the client to make at various points during
#   execution. The SSL handshake protocol or the server can initiate one of these choices
#   to be made by the client.


choices = {"KEY_EXCHANGE": ['RSA'],#, 'Fixed Diffie-Hellman', 'Ephemeral Diffie-Hellman', 'Anonymous Diffie-Hellman'], 
        "CIPHER_SUITE": ['DES'],#, 'textbook RSA'], 
        "HASH": ['SHA-1']}

class choice:
    def __init__(self, choice, chosen = None, one_pick = True):
        self.choice = choice
        self.choose_one = one_pick
        try:
            self.choices = choices[choice]
        except:
            print("Bad choice option.")
            return 
        if chosen is not None:
            self.chosen = chosen
    
    def get_choice(self):
        return self.choices[self.chosen.index('1')]

    def prompt(self):
        if len(self.choices) == 1:
            self.chosen = '1'
            return self.chosen
        self.chosen = []
        for l in self.choices:
            self.chosen.append('0')
        while True:
            this_choice = input("Pick a " + self.choice + " options are: " + str(self.choices) + ":\n")
            if this_choice not in self.choices:
                if this_choice == "q":
                    chosen_str = ''
                    for l in self.chosen:
                        chosen_str += l
                    return chosen_str
                print("Choose something in this list: " + str(self.choices))
                continue
            else:
                self.chosen[self.choices.index(this_choice)] = '1'
                if self.choose_one:
                    chosen_str = ''
                    for l in self.chosen:
                        chosen_str += l
                    return chosen_str
                else:
                    print("write \'q\' to quit, otherwise choose something else from this list \n")
                    continue



        
