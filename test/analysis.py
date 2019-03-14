"""
CSCI 5742 Final Project
Vedant Singhania & Jacob Jolly

PROJECT NAME: Honeypot Analysis Tool
PROJECT DDESCRIPTION: The H.AT. takes data from the modified Adminer Log file
                      and parses it into IP Addresses, Usernames, and Passwords
                      if they were an Invalid Login. It then gives the user the
                      choice to look at graphs of each of the three and see if
                      are any connections and then determine if an IP Address
                      is an attacker.
"""

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import numpy as np
import ipaddress
import requests

LARGE_FONT = ("Verdana", 12)

class HATAnalysis(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        tk.Tk.wm_title(self, "Honeypot Analysis Tool")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (Main, UsernameGraphPage, PasswordGraphPage, IPAddressesGraphPage):
            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(Main)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class Main(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Start Page", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        # Create button for Analysis
        btn = ttk.Button(self, text="IP Analysis",
                            command=self.ipanalysis)
        btn.pack()

        # Create button for Username Graph Page
        btn2 = ttk.Button(self, text="Top Username Graph",
                             command=lambda: controller.show_frame(UsernameGraphPage))
        btn2.pack()

        # Create button for Password Graph Page
        btn3 = ttk.Button(self, text="Top Password Graph",
                             command=lambda: controller.show_frame(PasswordGraphPage))
        btn3.pack()

        # Create button for IP Address Graph Page
        btn4 = ttk.Button(self, text="Top IP Address Graph",
                             command=lambda: controller.show_frame(IPAddressesGraphPage))
        btn4.pack()

    # IP Analyzer Function
    def ipanalysis(self):
        text = "log.csv"
        IPAdds = []; IPCluData = []; IPTimes = []; IPPages = []
        IPAgent = []; IPUser = []; IPPass = []
        APIKey = "6cec2419ee3377ca5124db685feeed1c"

        with open(text, "r") as f:
            # Read in file line by line and add IP addresses to arrays
            for line in f:
                IPAdds.append(line.split(',')[1])

                # Add ip address into array to be clustered together
                IPCluData.append(int(ipaddress.ip_address(line.split(',')[1])))

            f.close()

        # Put Latitude, Longitude, Country, and Region into arrays
        IPLats, IPLons, IPCouns, IPRegs = self.getGeoData(APIKey, IPAdds)

        # When Analysis is done, pop up window displays 'Analysis Completed'
        messagebox.showinfo(title="Python H.A.T.", message="Analysis Completed")

    # Latitude/Longitude Function to find Geo location from IP Addresses using FreeGeoIP web service
    def getGeoData(self, apikey, ip_list=[], lats=[], lons=[], countries=[], regions=[]):
        # Go through IP list and request information about them from FreeGeoIP
        for ip in ip_list:
            r = requests.get("http://api.ipstack.com/" + ip + "?access_key=" + apikey)
            json_response = r.json()
            print("{ip}, {region_name}, {country_name}, {latitude}, {longitude}".format(**json_response))

            # Parse the JSON data into needed parts
            if json_response['latitude'] and json_response['longitude']:
                lats.append(json_response['latitude'])
                lons.append(json_response['longitude'])
            if json_response['country_name'] and json_response['region_name']:
                countries.append(json_response['country_name'])
                regions.append(json_response['region_name'])

        return lats, lons, countries, regions


# Page to Graph Usernames
class UsernameGraphPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Top Username Graph Page", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        btn = ttk.Button(self, text="Back to Home",
                             command=lambda: controller.show_frame(Main))
        btn.pack()

        # Function to count how many of an element there are in a list
        def countX(lst, x):
            return lst.count(x)

        # Function to sort the Seen elements according to what the counted elements
        # would be in ascending order
        def sort_list(list1, list2):
            zipped_pairs = zip(list2, list1)
            z = [x for _, x in sorted(zipped_pairs)]

            return z

        text = "log.csv"
        Usernames = []

        with open(text, "r") as f:
            # Read in file line by line and add IP addresses to arrays
            for line in f:
                split = line.split(',')

                if (split[2] == "INVALIDLOGIN"):
                    Usernames.append(split[3])

            f.close()

        SeenUsers = []
        UserCount = []

        # Make a list of Usernames seen, count how many there are, and add it to UserCount
        for user in Usernames:
            if user in SeenUsers:
                continue
            else:
                SeenUsers.append(user)

            UserCount.append(countX(Usernames, user))

        # Sort Seen list according to the ascending order UserCount could be
        SeenSort = sort_list(SeenUsers, UserCount)
        UserCount.sort()

        # Add a bar graph to the page to display
        f = Figure(figsize=(5, 5), dpi=100)
        a = f.add_subplot(111)
        a.bar(SeenUsers, UserCount)

        canvas = FigureCanvasTkAgg(f, self)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self)
        toolbar.update()
        canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


# Page to Graph Passwords
class PasswordGraphPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Top Password Graph Page", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        btn = ttk.Button(self, text="Back to Home",
                             command=lambda: controller.show_frame(Main))
        btn.pack()

        # Function to count how many of an element there are in a list
        def countX(lst, x):
            return lst.count(x)

        # Function to sort the Seen elements according to what the counted elements
        # would be in ascending order
        def sort_list(list1, list2):
            zipped_pairs = zip(list2, list1)
            z = [x for _, x in sorted(zipped_pairs)]

            return z

        text = "log.csv"
        Passwords = []

        with open(text, "r") as f:
            # Read in file line by line and add Passwords to arrays
            for line in f:
                split = line.split(',')

                if (split[2] == "INVALIDLOGIN"):
                    Passwords.append(split[4])

            f.close()

        SeenPasses = []
        PassCount = []

        # Make a list of passwords seen, count how many there are, and add it to PassCount
        for password in Passwords:
            if password in SeenPasses:
                continue
            else:
                SeenPasses.append(password)

            PassCount.append(countX(Passwords, password))

        # Sort Seen list according to the ascending order PassCount could be
        SeenSort = sort_list(SeenPasses, PassCount)
        PassCount.sort()

        # Add a bar graph to the page to display
        f = Figure(figsize=(5, 5), dpi=100)
        a = f.add_subplot(111)
        a.bar(SeenSort, PassCount, align='center')

        canvas = FigureCanvasTkAgg(f, self)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self)
        toolbar.update()
        canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


# Page to Graph IP Addresses
class IPAddressesGraphPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Top IP Address Graph Page", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        btn = ttk.Button(self, text="Back to Home",
                             command=lambda: controller.show_frame(Main))
        btn.pack()

        # Function to count how many of an element there are in a list
        def countX(lst, x):
            return lst.count(x)

        # Function to sort the Seen elements according to what the counted elements
        # would be in ascending order
        def sort_list(list1, list2):
            zipped_pairs = zip(list2, list1)
            z = [x for _, x in sorted(zipped_pairs)]

            return z

        text = "log.csv"
        Addresses = []

        with open(text, "r") as f:
            # Read in file line by line and add IP addresses to arrays
            for line in f:
                split = line.split(',')

                if (split[2] == "INVALIDLOGIN"):
                    Addresses.append(split[1])

            f.close()

        SeenAdds = []
        AddsCount = []

        # Make a list of addresses seen, count how many there are, and add it to AddsCount
        for addr in Addresses:
            if addr in SeenAdds:
                continue
            else:
                SeenAdds.append(addr)

            AddsCount.append(countX(Addresses, addr))

        # Sort Seen list according to the ascending order PassCount could be
        SeenSort = sort_list(SeenAdds, AddsCount)
        AddsCount.sort()

        # Add a bar graph to the page to display
        f = Figure(figsize=(5, 5), dpi=100)
        a = f.add_subplot(111)
        a.bar(SeenSort, AddsCount)

        canvas = FigureCanvasTkAgg(f, self)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(canvas, self)
        toolbar.update()
        canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)


# Iitialize and start the Main page
tool = HATAnalysis()
tool.mainloop()
