import pyfiglet


class WelcomeMessage:
    def __init__(self):
        self.ascii_banner1 = pyfiglet.figlet_format("Mr Roboto \n", 'slant')

    def execute(self):
        print(self.ascii_banner1, "\n")
